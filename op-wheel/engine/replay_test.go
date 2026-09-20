package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadChainConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	genesis := `{"config":{"chainId":901,"canyonTime":0,"ecotoneTime":17000},"nonce":"0x0","alloc":{}}`
	chainCfg := `{"chainId":901,"canyonTime":0,"ecotoneTime":17000}`
	// a rollup config parses as JSON, but is not a chain config
	rollupCfg := `{"genesis":{"l2_time":0},"block_time":2,"seq_window_size":3600}`

	tests := []struct {
		name    string
		path    string
		chainID uint64
		ecotone uint64
		wantErr bool
	}{
		{"genesis file", write("genesis.json", genesis), 901, 17000, false},
		{"bare chain config", write("chain.json", chainCfg), 901, 17000, false},
		{"rollup config", write("rollup.json", rollupCfg), 0, 0, true},
		{"not json", write("junk.json", "hello"), 0, 0, true},
		{"missing file", filepath.Join(dir, "nope.json"), 0, 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := LoadChainConfig(test.path)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got chain id %v", cfg.ChainID)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.ChainID.Uint64() != test.chainID {
				t.Fatalf("chain id: got %v, want %d", cfg.ChainID, test.chainID)
			}
			if cfg.EcotoneTime == nil || *cfg.EcotoneTime != test.ecotone {
				t.Fatalf("ecotone time: got %v, want %d", cfg.EcotoneTime, test.ecotone)
			}
		})
	}
}
