#!/usr/bin/env node

"use strict";

// Deterministically rasterize the site's small vector mark with Node core
// only. Apple touch icons must be opaque squares; iOS applies its own mask.

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const OUTPUT = path.resolve("static");
const BACKGROUND = [4, 16, 15];
const GRADIENT_START = [67, 245, 223];
const GRADIENT_END = [31, 188, 169];
const GRADIENT_FROM = [6, 5];
const GRADIENT_TO = [30, 31];
const STROKE_RADIUS = 1.1;
const SAMPLES = 4;

const SEGMENTS = [
  [[18, 5], [30, 11.5]],
  [[30, 11.5], [18, 18]],
  [[18, 18], [6, 11.5]],
  [[6, 11.5], [18, 5]],
  [[29, 17], [18, 23]],
  [[18, 23], [7, 17]],
  [[29, 23], [18, 29]],
  [[18, 29], [7, 23]],
];

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const name = Buffer.from(type, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, checksum]);
}

function distanceToSegment(point, start, end) {
  const dx = end[0] - start[0];
  const dy = end[1] - start[1];
  const denominator = dx * dx + dy * dy;
  const projection = denominator
    ? Math.max(0, Math.min(1, ((point[0] - start[0]) * dx + (point[1] - start[1]) * dy) / denominator))
    : 0;
  const x = start[0] + projection * dx;
  const y = start[1] + projection * dy;
  return Math.hypot(point[0] - x, point[1] - y);
}

function markColor(point) {
  const dx = GRADIENT_TO[0] - GRADIENT_FROM[0];
  const dy = GRADIENT_TO[1] - GRADIENT_FROM[1];
  const t = Math.max(0, Math.min(1,
    ((point[0] - GRADIENT_FROM[0]) * dx + (point[1] - GRADIENT_FROM[1]) * dy) / (dx * dx + dy * dy),
  ));
  return GRADIENT_START.map((channel, index) =>
    Math.round(channel + (GRADIENT_END[index] - channel) * t),
  );
}

function render(size) {
  const stride = size * 3 + 1;
  const scanlines = Buffer.alloc(stride * size);
  for (let y = 0; y < size; y += 1) {
    scanlines[y * stride] = 0;
    for (let x = 0; x < size; x += 1) {
      let coverage = 0;
      const foreground = [0, 0, 0];
      for (let sy = 0; sy < SAMPLES; sy += 1) {
        for (let sx = 0; sx < SAMPLES; sx += 1) {
          const point = [
            ((x + (sx + 0.5) / SAMPLES) / size) * 36,
            ((y + (sy + 0.5) / SAMPLES) / size) * 36,
          ];
          if (SEGMENTS.some(([start, end]) => distanceToSegment(point, start, end) <= STROKE_RADIUS)) {
            const color = markColor(point);
            for (let channel = 0; channel < 3; channel += 1) foreground[channel] += color[channel];
            coverage += 1;
          }
        }
      }
      const sampleCount = SAMPLES * SAMPLES;
      const offset = y * stride + 1 + x * 3;
      for (let channel = 0; channel < 3; channel += 1) {
        const averageForeground = coverage ? foreground[channel] / coverage : BACKGROUND[channel];
        scanlines[offset + channel] = Math.round(
          (averageForeground * coverage + BACKGROUND[channel] * (sampleCount - coverage)) / sampleCount,
        );
      }
    }
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 2; // RGB: deliberately no alpha channel.
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([
    signature,
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(scanlines, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

const outputs = [
  ["apple-touch-icon.png", 180],
  ["apple-touch-icon-180x180.png", 180],
  ["icon-192x192.png", 192],
  ["icon-512x512.png", 512],
  ["icon-maskable-512x512.png", 512],
];

fs.mkdirSync(OUTPUT, { recursive: true });
for (const [name, size] of outputs) {
  const target = path.join(OUTPUT, name);
  fs.writeFileSync(target, render(size));
  console.log(`wrote ${path.relative(process.cwd(), target)} (${size}x${size}, opaque RGB)`);
}
