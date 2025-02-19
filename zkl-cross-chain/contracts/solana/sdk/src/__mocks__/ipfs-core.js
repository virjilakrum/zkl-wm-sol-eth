const mockIPFS = {
  _storage: new Map(),
  _pinnedFiles: new Set(),
  _contentMap: new Map(),
  _nextCid: 0,
  
  add: jest.fn().mockImplementation((content) => {
    const cid = `QmTest${mockIPFS._nextCid}`;
    mockIPFS._storage.set(cid, content);
    mockIPFS._contentMap.set(cid, content);
    mockIPFS._nextCid++;
    return Promise.resolve({ cid: { toString: () => cid } });
  }),
  
  cat: jest.fn().mockImplementation(function* (cid) {
    yield mockIPFS._contentMap.get(cid);
  }),
  
  pin: {
    add: jest.fn().mockImplementation((cid) => {
      mockIPFS._pinnedFiles.add(cid);
      return Promise.resolve();
    }),
    
    rm: jest.fn().mockImplementation((cid) => {
      mockIPFS._pinnedFiles.delete(cid);
      return Promise.resolve();
    }),
    
    ls: jest.fn().mockImplementation(function* () {
      for (const cid of mockIPFS._pinnedFiles) {
        yield { cid: { toString: () => cid } };
      }
    })
  },
  
  reset: jest.fn().mockImplementation(() => {
    mockIPFS._pinnedFiles.clear();
    mockIPFS._storage.clear();
    mockIPFS._contentMap.clear();
    mockIPFS._nextCid = 0;
  }),
  
  stop: jest.fn().mockResolvedValue(undefined),
  
  // Test yardımcı metodları
  _getContent: function(cid) {
    return this._contentMap.get(cid);
  },

  _getPinnedFiles: function() {
    return Array.from(this._pinnedFiles);
  }
};

const create = jest.fn().mockResolvedValue(mockIPFS);

module.exports = { create };
