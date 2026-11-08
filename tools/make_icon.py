import struct, sys, zlib

# 128x128 shield glyph on a teal tile, drawn without third-party libraries.
W = H = 128
bg, fg, ck = (17, 94, 89), (240, 253, 250), (17, 94, 89)
rows = []
for y in range(H):
    row = bytearray([0])
    for x in range(W):
        c = bg
        cx = x - 64
        top, bottom = 24, 108
        if top <= y <= bottom:
            half = 36 if y < 70 else 36 * (bottom - y) / (bottom - 70)
            if abs(cx) <= half:
                c = fg
                # check mark
                if (abs((y - 66) - (cx + 14) * -1) < 5 and -22 <= cx <= -6) or \
                   (abs((y - 74) + (cx + 6) * 1.1) < 5 and -6 <= cx <= 22):
                    c = ck
        row += bytes(c)
    rows.append(bytes(row))
raw = zlib.compress(b"".join(rows), 9)
chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0)) + chunk(b"IDAT", raw) + chunk(b"IEND", b"")
open(sys.argv[1], "wb").write(png)
