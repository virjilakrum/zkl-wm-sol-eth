module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: 'tsconfig.json',
      isolatedModules: false,
      diagnostics: {
        ignoreCodes: [1005, 1183]
      }
    }],
    '^.+\\.jsx?$': ['babel-jest', {
      presets: [
        ['@babel/preset-env', { targets: { node: 'current' }, modules: 'commonjs' }]
      ]
    }]
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  testMatch: ['**/__tests__/**/*.[jt]s?(x)', '**/?(*.)+(spec|test).[jt]s?(x)'],
  transformIgnorePatterns: [
    'node_modules/(?!(@solana/web3.js|@wormhole-foundation)/)'
  ],
  moduleNameMapper: {
    '^ecies-wasm$': '<rootDir>/src/__mocks__/ecies-wasm.js',
    '^@zklx/kds$': '<rootDir>/src/__mocks__/kds.js',
    '^ipfs-http-client$': '<rootDir>/src/__mocks__/ipfs-http-client.js',
    '^ipfs-core$': '<rootDir>/src/__mocks__/ipfs-core.js'
  }
}; 