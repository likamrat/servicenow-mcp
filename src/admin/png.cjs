const crypto = require("node:crypto");
const { inflateSync, crc32 } = require("node:zlib");
const PNG = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

function inspectPng(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length >= 120000 || bytes.length < 45 || !bytes.subarray(0, 8).equals(PNG))
    throw new Error("Invalid PNG signature or size.");
  let offset = 8, width, height, channels, header = false, dataEnded = false, ended = false;
  const data = [];
  while (offset < bytes.length) {
    if (offset + 12 > bytes.length) throw new Error("Truncated PNG chunk.");
    const length = bytes.readUInt32BE(offset);
    const type = bytes.toString("ascii", offset + 4, offset + 8);
    const end = offset + 12 + length;
    if (!/^[A-Za-z]{4}$/.test(type) || end > bytes.length ||
        crc32(bytes.subarray(offset + 4, offset + 8 + length)) !== bytes.readUInt32BE(offset + 8 + length))
      throw new Error("Invalid PNG chunk or CRC.");
    const content = bytes.subarray(offset + 8, offset + 8 + length);
    if (!header && type !== "IHDR") throw new Error("PNG header missing.");
    if (type === "IHDR") {
      if (header || length !== 13) throw new Error("Invalid PNG header.");
      width = content.readUInt32BE(0); height = content.readUInt32BE(4);
      if (!width || !height || width > 400 || height > 50) throw new Error("Logo exceeds 400 by 50 pixels.");
      if (content[8] !== 8 || ![2, 6].includes(content[9]) || content[10] || content[11] || content[12])
        throw new Error("Logo requires static noninterlaced 8-bit RGB or RGBA PNG.");
      channels = content[9] === 6 ? 4 : 3;
      header = true;
    } else if (type === "IDAT") {
      if (dataEnded) throw new Error("Invalid PNG data order.");
      data.push(content);
    } else if (type === "IEND") {
      if (length || !data.length || end !== bytes.length) throw new Error("Invalid PNG end.");
      ended = true;
    } else {
      if (["acTL", "fcTL", "fdAT"].includes(type)) throw new Error("Animated logo unsupported.");
      if (type[0] === type[0].toUpperCase() && type !== "PLTE") throw new Error("Unsupported critical PNG chunk.");
      if (data.length) dataEnded = true;
    }
    offset = end;
  }
  if (!ended) throw new Error("PNG end missing.");
  const rowLength = width * channels + 1;
  const pixels = inflateSync(Buffer.concat(data), { maxOutputLength: rowLength * height + 1 });
  if (pixels.length !== rowLength * height) throw new Error("Invalid PNG pixel length.");
  for (let row = 0; row < height; row++) if (pixels[row * rowLength] > 4) throw new Error("Invalid PNG filter.");
  return { content_type: "image/png", bytes: bytes.length, width, height, channels,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
}

module.exports = { inspectPng };
