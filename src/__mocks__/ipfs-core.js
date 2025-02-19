const mockIPFS = {
  _storage: new Map(),
  _pinnedFiles: new Set(),
  _contentMap: new Map(),
  _nextCid: 0,
  add: jest.fn().mockImplementation((content) => {
    const cid = `QmTest${mockIPFS._nextCid++}`;
    mockIPFS._storage.set(cid, content);
    mockIPFS._contentMap.set(cid, content);
    return Promise.resolve({ cid: { toString: () => cid } });
  }),
  cat: jest.fn().mockImplementation((cid) => {
    return Promise.resolve(mockIPFS._contentMap.get(cid));
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
  },
  reset: jest.fn().mockImplementation(() => {
    mockIPFS._pinnedFiles.clear();
    mockIPFS._storage.clear();
    mockIPFS._contentMap.clear();
    mockIPFS._nextCid = 0;
  }),
  getPinnedFiles: jest.fn().mockImplementation(() => {
    return Array.from(mockIPFS._pinnedFiles);
  }),
};

module.exports = jest.fn(() => Promise.resolve(mockIPFS)); 