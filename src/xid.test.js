import genXid from './xid.js';

describe('genXid', () => {
  it('should generate a 20-character base32hex string', () => {
    const id = genXid();
    expect(typeof id).toBe('string');
    expect(id.length).toBe(20);
    expect(id).toMatch(/^[0-9a-v]{20}$/);
  });

  it('should generate unique IDs', () => {
    const ids = new Set();
    for (let i = 0; i < 1000; i++) {
      ids.add(genXid());
    }
    expect(ids.size).toBe(1000);
  });
});
