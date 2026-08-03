const TABLE = new Uint32Array(256);
for (let index = 0; index < 256; index += 1) {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) === 1 ? 0x82f63b78 ^ (value >>> 1) : value >>> 1;
  }
  TABLE[index] = value >>> 0;
}

export function crc32c(bytes) {
  let checksum = 0xffffffff;
  for (const byte of bytes) {
    checksum = TABLE[(checksum ^ byte) & 0xff] ^ (checksum >>> 8);
  }
  return (checksum ^ 0xffffffff) >>> 0;
}
