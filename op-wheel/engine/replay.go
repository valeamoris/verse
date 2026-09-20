package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"

	"github.com/ethereum-optimism/optimism/op-service/client"
	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum-optimism/optimism/op-service/retry"
	"github.com/ethereum-optimism/optimism/op-service/sources"
)

// LoadChainConfig reads a chain config from a JSON file. The file may be a geth-style chain
// config object, or a genesis file with a "config" field, as op-geth and op-reth use.
func LoadChainConfig(path string) (*params.ChainConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain config %q: %w", path, err)
	}
	var genesis struct {
		Config *params.ChainConfig `json:"config"`
	}
	if err := json.Unmarshal(data, &genesis); err == nil && genesis.Config != nil {
		return genesis.Config, nil
	}
	var cfg params.ChainConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse chain config %q: %w", path, err)
	}
	// A chain config without a chain ID means the file was something else entirely, e.g. a rollup
	// config: silently continuing would pick the wrong fork schedule for every block.
	if cfg.ChainID == nil {
		return nil, fmt.Errorf("chain config %q has no chainId, is it a genesis or chain config file?", path)
	}
	return &cfg, nil
}

// ReplaySettings configures a trusted chain replay.
type ReplaySettings struct {
	// Start is the first block number to replay. If zero, replay resumes at destination head + 1.
	Start uint64
	// End is the last block number to replay. If zero, the source head is used.
	End uint64
	// FCUInterval is how often forkchoiceUpdated is called during the replay, so the
	// destination persists progress instead of buffering the whole chain in memory.
	// Zero disables periodic forkchoice updates.
	FCUInterval uint64
	// LogInterval is how often progress is logged, in blocks.
	LogInterval uint64
	// SafeOffset, when non-zero, marks (head - SafeOffset) as safe and finalized on the
	// destination, instead of mirroring the source node's safe/finalized labels.
	SafeOffset uint64
}

// Replay executes every L2 block in the configured range on the destination engine, taking the
// blocks from a trusted, plain eth RPC source (e.g. op-geth). No L1 data is read at all, so this
// works even when the historical L1 blob data needed to derive the chain is no longer available.
//
// The source is trusted: blocks are executed and validated by the destination, but the chain is
// not verified against L1 data availability. Forkchoice on the destination is pointed at the
// replayed chain at the end, so that an op-node started afterwards begins derivation near the
// tip rather than at L2 genesis.
func Replay(ctx context.Context, lgr log.Logger, source client.RPC, dest *sources.EngineAPIClient,
	cfg *params.ChainConfig, s ReplaySettings) error {

	destHead, err := getHeader(ctx, dest.RPC, methodEthGetBlockByNumber, "latest")
	if err != nil {
		return fmt.Errorf("failed to read destination head: %w", err)
	}
	srcHead, err := getHeader(ctx, source, methodEthGetBlockByNumber, "latest")
	if err != nil {
		return fmt.Errorf("failed to read source head: %w", err)
	}
	genesis, err := getHeader(ctx, source, methodEthGetBlockByNumber, "0x0")
	if err != nil {
		return fmt.Errorf("failed to read genesis block from source: %w", err)
	}

	start := s.Start
	if start == 0 {
		start = destHead.Number.Uint64() + 1
	}
	end := s.End
	if end == 0 {
		end = srcHead.Number.Uint64()
	}

	lgr.Info("Starting chain replay", "start", start, "end", end,
		"dest_head", destHead.Number, "source_head", srcHead.Number, "genesis", genesis.Hash())

	var head *types.Block
	if start > end {
		lgr.Info("Nothing to replay: destination is already at or past the requested end")
		if destHead.Number.Uint64() > 0 {
			head = types.NewBlockWithHeader(destHead)
		}
	} else {
		started := time.Now()
		var done uint64
		for n := start; n <= end; n++ {
			block, err := retry.Do(ctx, 5, retry.Exponential(), func() (*types.Block, error) {
				return getBlock(ctx, source, methodEthGetBlockByNumber, hexutil.EncodeUint64(n))
			})
			if err != nil {
				return fmt.Errorf("failed to fetch block %d from source: %w", n, err)
			}
			if err := insertPayload(ctx, dest, block, cfg); err != nil {
				return fmt.Errorf("failed to insert block %d (%s): %w", n, block.Hash(), err)
			}
			head = block
			done++
			if s.FCUInterval > 0 && n%s.FCUInterval == 0 {
				if err := updateForkchoice(ctx, dest, block.Hash(), genesis.Hash(), genesis.Hash()); err != nil {
					return fmt.Errorf("failed to update forkchoice at block %d: %w", n, err)
				}
				lgr.Info("Forkchoice updated", "head", n, "hash", block.Hash())
			}
			if s.LogInterval > 0 && done%s.LogInterval == 0 {
				elapsed := time.Since(started)
				rate := float64(done) / elapsed.Seconds()
				var eta time.Duration
				if rate > 0 {
					eta = time.Duration(math.Round(float64(end-n)/rate)) * time.Second
				}
				lgr.Info("Replay progress", "block", n, "of", end,
					"blocks_per_sec", math.Round(rate*10)/10,
					"elapsed", elapsed.Round(time.Second), "eta", eta.Round(time.Minute))
			}
		}
	}

	if head == nil {
		return fmt.Errorf("no block available to set forkchoice to")
	}

	// Point forkchoice at the replayed chain. op-node derives from the L1 origin of these labels,
	// so a label near the tip is what keeps the op-node from re-deriving (and re-fetching L1
	// blobs for) the entire chain.
	safeHash, safeNum, finalizedHash, err := resolveLabels(ctx, lgr, source, head, s.SafeOffset)
	if err != nil {
		return err
	}
	if err := updateForkchoice(ctx, dest, head.Hash(), safeHash, finalizedHash); err != nil {
		return fmt.Errorf("failed to set final forkchoice: %w", err)
	}
	behind := head.NumberU64() - safeNum
	lgr.Info("Replay finished, forkchoice set", "head", head.NumberU64(), "head_hash", head.Hash(),
		"safe", safeNum, "safe_hash", safeHash, "finalized", finalizedHash, "safe_behind_head", behind)
	if behind > 100_000 {
		lgr.Warn("The destination's safe head is far behind its head. op-node will walk back this range "+
			"on startup; re-run with --safe-offset to place the labels closer to the tip.",
			"safe_behind_head", behind)
	}
	return nil
}

// resolveLabels picks the safe/finalized labels to apply to the destination, and reports the
// block number of the chosen safe label.
func resolveLabels(ctx context.Context, lgr log.Logger, source client.RPC, head *types.Block, safeOffset uint64) (common.Hash, uint64, common.Hash, error) {
	headNum := head.NumberU64()
	if safeOffset > 0 {
		num := uint64(0)
		if headNum > safeOffset {
			num = headNum - safeOffset
		}
		h, err := getHeader(ctx, source, methodEthGetBlockByNumber, hexutil.EncodeUint64(num))
		if err != nil {
			return common.Hash{}, 0, common.Hash{}, fmt.Errorf("failed to fetch block %d for the safe-offset labels: %w", num, err)
		}
		return h.Hash(), num, h.Hash(), nil
	}
	srcSafe, err := getHeader(ctx, source, methodEthGetBlockByNumber, "safe")
	if err != nil {
		return common.Hash{}, 0, common.Hash{}, fmt.Errorf("failed to read the source safe head: %w", err)
	}
	srcFinalized, err := getHeader(ctx, source, methodEthGetBlockByNumber, "finalized")
	if err != nil {
		return common.Hash{}, 0, common.Hash{}, fmt.Errorf("failed to read the source finalized head: %w", err)
	}
	if srcSafe.Number.Uint64() > headNum || srcFinalized.Number.Uint64() > headNum {
		lgr.Warn("Source safe/finalized head is ahead of the replayed head, clamping to the replayed head",
			"source_safe", srcSafe.Number, "source_finalized", srcFinalized.Number, "replayed_head", headNum)
	}
	if srcSafe.Number.Uint64() > headNum {
		srcSafe = head.Header()
	}
	if srcFinalized.Number.Uint64() > srcSafe.Number.Uint64() {
		srcFinalized = srcSafe
	}
	return srcSafe.Hash(), srcSafe.Number.Uint64(), srcFinalized.Hash(), nil
}

// insertPayload turns the block into an execution payload and executes it on the destination,
// retrying transient RPC failures and SYNCING/ACCEPTED statuses.
func insertPayload(ctx context.Context, dest *sources.EngineAPIClient, block *types.Block, cfg *params.ChainConfig) error {
	payloadEnv, err := eth.BlockAsPayloadEnv(block, cfg)
	if err != nil {
		return fmt.Errorf("failed to convert block to execution payload: %w", err)
	}
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
			}
		}
		status, err := dest.NewPayload(ctx, payloadEnv.ExecutionPayload, payloadEnv.ParentBeaconBlockRoot)
		if err != nil {
			lastErr = err // transient RPC error
			continue
		}
		switch status.Status {
		case eth.ExecutionValid:
			return nil
		case eth.ExecutionSyncing, eth.ExecutionAccepted:
			lastErr = eth.NewPayloadErr(payloadEnv.ExecutionPayload, status)
			continue
		default:
			return eth.NewPayloadErr(payloadEnv.ExecutionPayload, status)
		}
	}
	return fmt.Errorf("payload insert failed after retries: %w", lastErr)
}
