export const proxyAdminAbi = [
  { type: 'function', name: 'owner', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'upgrade', stateMutability: 'nonpayable', inputs: [{ name: '_proxy', type: 'address' }, { name: '_implementation', type: 'address' }], outputs: [] },
  { type: 'function', name: 'upgradeAndCall', stateMutability: 'payable', inputs: [{ name: '_proxy', type: 'address' }, { name: '_implementation', type: 'address' }, { name: '_data', type: 'bytes' }], outputs: [] },
  { type: 'function', name: 'changeProxyAdmin', stateMutability: 'nonpayable', inputs: [{ name: '_proxy', type: 'address' }, { name: '_newAdmin', type: 'address' }], outputs: [] },
] as const

export const systemConfigAbi = [
  { type: 'function', name: 'owner', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'setUnsafeBlockSigner', stateMutability: 'nonpayable', inputs: [{ name: '_unsafeBlockSigner', type: 'address' }], outputs: [] },
  { type: 'function', name: 'setBatcherHash', stateMutability: 'nonpayable', inputs: [{ name: '_batcherHash', type: 'bytes32' }], outputs: [] },
  { type: 'function', name: 'setGasConfig', stateMutability: 'nonpayable', inputs: [{ name: '_overhead', type: 'uint256' }, { name: '_scalar', type: 'uint256' }], outputs: [] },
  { type: 'function', name: 'setGasConfigEcotone', stateMutability: 'nonpayable', inputs: [{ name: '_basefeeScalar', type: 'uint32' }, { name: '_blobbasefeeScalar', type: 'uint32' }], outputs: [] },
  { type: 'function', name: 'setGasLimit', stateMutability: 'nonpayable', inputs: [{ name: '_gasLimit', type: 'uint64' }], outputs: [] },
  { type: 'function', name: 'setEIP1559Params', stateMutability: 'nonpayable', inputs: [{ name: '_denominator', type: 'uint32' }, { name: '_elasticity', type: 'uint32' }], outputs: [] },
  { type: 'function', name: 'setMinBaseFee', stateMutability: 'nonpayable', inputs: [{ name: '_minBaseFee', type: 'uint64' }], outputs: [] },
  { type: 'function', name: 'setOperatorFeeScalars', stateMutability: 'nonpayable', inputs: [{ name: '_operatorFeeScalar', type: 'uint32' }, { name: '_operatorFeeConstant', type: 'uint64' }], outputs: [] },
  { type: 'function', name: 'setFeature', stateMutability: 'nonpayable', inputs: [{ name: '_feature', type: 'bytes32' }, { name: '_enabled', type: 'bool' }], outputs: [] },
  { type: 'function', name: 'configureGasPayingTokenInPortal', stateMutability: 'nonpayable', inputs: [], outputs: [] },
  { type: 'function', name: 'transferOwnership', stateMutability: 'nonpayable', inputs: [{ name: 'newOwner', type: 'address' }], outputs: [] },
] as const

export const superchainConfigAbi = [
  { type: 'function', name: 'pause', stateMutability: 'nonpayable', inputs: [{ name: '_identifier', type: 'address' }], outputs: [] },
  { type: 'function', name: 'unpause', stateMutability: 'nonpayable', inputs: [{ name: '_identifier', type: 'address' }], outputs: [] },
  { type: 'function', name: 'extend', stateMutability: 'nonpayable', inputs: [{ name: '_identifier', type: 'address' }], outputs: [] },
  { type: 'function', name: 'paused', stateMutability: 'view', inputs: [{ name: '_identifier', type: 'address' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'guardian', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
] as const

export const guardAbi = [
  { type: 'function', name: 'timelockConfiguration', stateMutability: 'view', inputs: [{ name: '_safe', type: 'address' }], outputs: [{ name: 'timelockDelay', type: 'uint256' }] },
  { type: 'function', name: 'scheduledTransaction', stateMutability: 'view', inputs: [{ name: '_safe', type: 'address' }, { name: '_txHash', type: 'bytes32' }], outputs: [{ name: 'executionTime', type: 'uint256' }, { name: 'state', type: 'uint8' }, { name: 'params', type: 'tuple', components: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }, { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' }, { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' }] }] },
  { type: 'function', name: 'scheduleTransaction', stateMutability: 'nonpayable', inputs: [{ name: '_safe', type: 'address' }, { name: '_nonce', type: 'uint256' }, { name: '_params', type: 'tuple', components: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }, { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' }, { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' }] }, { name: '_signatures', type: 'bytes' }], outputs: [] },
] as const
