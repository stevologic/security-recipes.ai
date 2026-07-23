"use strict";

const CP1252_CONTINUATION_CHARS = new Set([
  ...Array.from({ length: 0x40 }, (_, index) => String.fromCodePoint(0x80 + index)),
  ..."€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ",
]);

const CP1252_BYTE_BY_CODE_POINT = new Map([
  [0x0192, 0x83], [0x0152, 0x8c], [0x0153, 0x9c], [0x0160, 0x8a],
  [0x0161, 0x9a], [0x0178, 0x9f], [0x017d, 0x8e], [0x017e, 0x9e],
  [0x02c6, 0x88], [0x02dc, 0x98], [0x2013, 0x96], [0x2014, 0x97],
  [0x2018, 0x91], [0x2019, 0x92], [0x201a, 0x82], [0x201c, 0x93],
  [0x201d, 0x94], [0x201e, 0x84], [0x2020, 0x86], [0x2021, 0x87],
  [0x2022, 0x95], [0x2026, 0x85], [0x2030, 0x89], [0x2039, 0x8b],
  [0x203a, 0x9b], [0x20ac, 0x80], [0x2122, 0x99],
]);

const RELEVANT_NAMED_ENTITIES = new Map(
  Object.entries({
    amp: "&",
    nbsp: " ",
    acirc: "â",
    atilde: "Ã",
    euro: "€",
    sbquo: "‚",
    fnof: "ƒ",
    bdquo: "„",
    hellip: "…",
    dagger: "†",
    circ: "ˆ",
    permil: "‰",
    scaron: "š",
    lsaquo: "‹",
    oelig: "œ",
    zcaron: "ž",
    lsquo: "‘",
    rsquo: "’",
    ldquo: "“",
    rdquo: "”",
    bull: "•",
    ndash: "–",
    mdash: "—",
    tilde: "˜",
    trade: "™",
    rsaquo: "›",
    yuml: "Ÿ",
  }),
);

function hasTextEncodingArtifact(value) {
  const text = String(value || "");
  if (/[\u0080-\u009f\ufffd]/u.test(text)) return true;

  for (let index = 0; index < text.length; index += 1) {
    const lead = text.codePointAt(index);
    const continuationCount =
      lead >= 0xc2 && lead <= 0xdf
        ? 1
        : lead >= 0xe0 && lead <= 0xef
          ? 2
          : lead >= 0xf0 && lead <= 0xf4
            ? 3
            : 0;
    if (!continuationCount || index + continuationCount >= text.length) continue;
    const candidates = text.slice(index + 1, index + 1 + continuationCount);
    if ([...candidates].every((character) => CP1252_CONTINUATION_CHARS.has(character))) {
      return true;
    }
  }
  return false;
}

function mojibakeByte(value, index) {
  const codePoint = value.codePointAt(index);
  if (codePoint <= 0xff) return codePoint;
  return CP1252_BYTE_BY_CODE_POINT.get(codePoint) ?? -1;
}

function utf8SequenceLength(firstByte) {
  if (firstByte >= 0xc2 && firstByte <= 0xdf) return 2;
  if (firstByte >= 0xe0 && firstByte <= 0xef) return 3;
  if (firstByte >= 0xf0 && firstByte <= 0xf4) return 4;
  return 0;
}

function decodedCodePoint(bytes) {
  const first = bytes[0];
  if (bytes.length === 2) return ((first & 0x1f) << 6) | (bytes[1] & 0x3f);
  if (bytes.length === 3) {
    if ((first === 0xe0 && bytes[1] < 0xa0) || (first === 0xed && bytes[1] >= 0xa0)) return -1;
    return ((first & 0x0f) << 12) | ((bytes[1] & 0x3f) << 6) | (bytes[2] & 0x3f);
  }
  if ((first === 0xf0 && bytes[1] < 0x90) || (first === 0xf4 && bytes[1] > 0x8f)) return -1;
  return ((first & 0x07) << 18) | ((bytes[1] & 0x3f) << 12) |
    ((bytes[2] & 0x3f) << 6) | (bytes[3] & 0x3f);
}

function repairMojibakePass(value) {
  let repaired = "";
  for (let index = 0; index < value.length;) {
    const firstByte = mojibakeByte(value, index);
    const sequenceLength = utf8SequenceLength(firstByte);
    const bytes = sequenceLength ? [firstByte] : [];
    for (let offset = 1; offset < sequenceLength; offset += 1) {
      const byte = mojibakeByte(value, index + offset);
      if (byte < 0x80 || byte > 0xbf) {
        bytes.length = 0;
        break;
      }
      bytes.push(byte);
    }
    const codePoint = sequenceLength > 0 && bytes.length === sequenceLength
      ? decodedCodePoint(bytes)
      : -1;
    if (codePoint >= 0) {
      repaired += String.fromCodePoint(codePoint);
      index += sequenceLength;
    } else {
      repaired += value[index];
      index += 1;
    }
  }
  return repaired;
}

function decodeTextEntitiesOnce(value) {
  return String(value || "").replace(
    /&(?:#(x[0-9a-f]+|\d+)|([a-z][a-z0-9]+));/giu,
    (entity, numeric, named) => {
      if (numeric) {
        const hexadecimal = numeric[0].toLowerCase() === "x";
        const codePoint = Number.parseInt(numeric.slice(hexadecimal ? 1 : 0), hexadecimal ? 16 : 10);
        if (
          Number.isSafeInteger(codePoint) &&
          codePoint >= 0 &&
          codePoint <= 0x10ffff &&
          !(codePoint >= 0xd800 && codePoint <= 0xdfff)
        ) {
          return String.fromCodePoint(codePoint);
        }
        return entity;
      }
      return RELEVANT_NAMED_ENTITIES.get(String(named).toLowerCase()) || entity;
    },
  );
}

function cleanCatalogText(value) {
  let text = String(value ?? "");
  for (let pass = 0; pass < 3; pass += 1) {
    const decoded = decodeTextEntitiesOnce(text);
    if (decoded === text) break;
    text = decoded;
  }
  for (let pass = 0; pass < 2; pass += 1) {
    const repaired = repairMojibakePass(text);
    if (repaired === text) break;
    text = repaired;
  }
  return text
    .replace(/\u00c2+(?=\s|$)/gu, "")
    .replace(/\uFFFDs\b/gu, "'s")
    .replace(/\uFFFD/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
}

function hasHtmlEncodingArtifact(value) {
  let text = String(value || "");
  for (let pass = 0; pass < 3; pass += 1) {
    if (hasTextEncodingArtifact(text)) return true;
    const decoded = decodeTextEntitiesOnce(text);
    if (decoded === text) return false;
    text = decoded;
  }
  return hasTextEncodingArtifact(text);
}

module.exports = {
  cleanCatalogText,
  decodeTextEntitiesOnce,
  hasHtmlEncodingArtifact,
  hasTextEncodingArtifact,
};
