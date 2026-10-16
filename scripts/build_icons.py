"""Generate the pixel mole SVG, PNGs and Windows ICO using only Python's stdlib."""
import argparse
from pathlib import Path
import struct
import zlib


ROOT = Path(__file__).resolve().parent.parent
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
PALETTE = {
    '.': (0, 0, 0, 0),
    'o': (16, 23, 26, 255),
    'f': (52, 68, 75, 255),
    'h': (82, 99, 106, 255),
    's': (38, 59, 66, 255),
    'c': (139, 205, 227, 255),
    'l': (34, 62, 72, 255),
    'i': (225, 242, 242, 255),
    'm': (227, 188, 157, 255),
    'p': (255, 155, 145, 255),
    'n': (183, 105, 110, 255),
}


def sprite():
    pixels = [['.'] * 16 for _ in range(16)]

    def rect(left, top, right, bottom, color):
        for y in range(top, bottom):
            pixels[y][left:right] = [color] * (right - left)

    for y, left, right in [(1, 5, 11), (2, 3, 13), (3, 2, 14),
                           (4, 2, 14), *[(y, 1, 15) for y in range(5, 12)],
                           (12, 2, 14), (13, 3, 13), (14, 2, 14)]:
        rect(left, y, right, y + 1, 'o')
        if y > 1:
            rect(left + 1, y, right - 1, y + 1, 'f')
    rect(5, 2, 9, 3, 'h')
    rect(3, 3, 7, 5, 'h')
    rect(2, 6, 14, 8, 's')
    for left in (3, 9):
        rect(left, 5, left + 4, 9, 'c')
        rect(left + 1, 6, left + 3, 8, 'l')
        rect(left + 1, 6, left + 2, 7, 'i')
    rect(7, 6, 9, 7, 'c')
    rect(4, 9, 12, 10, 's')
    rect(5, 9, 11, 12, 'm')
    rect(6, 12, 10, 13, 'm')
    rect(7, 10, 9, 11, 'p')
    rect(7, 11, 9, 12, 'n')
    rect(3, 13, 6, 15, 'o')
    rect(10, 13, 13, 15, 'o')
    rect(3, 13, 5, 14, 'm')
    rect(11, 13, 13, 14, 'm')
    return pixels


PIXELS = sprite()


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack(
        '>I', zlib.crc32(kind + data))


def png(size):
    rows = b''.join(b'\0' + b''.join(
        bytes(PALETTE[PIXELS[y * 16 // size][x * 16 // size]])
        for x in range(size)) for y in range(size))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack(
        '>2I5B', size, size, 8, 6, 0, 0, 0))
        + chunk(b'IDAT', zlib.compress(rows, 9)) + chunk(b'IEND', b''))


def svg():
    rectangles = []
    for y, row in enumerate(PIXELS):
        x = 0
        while x < len(row):
            color = row[x]
            end = x + 1
            while end < len(row) and row[end] == color:
                end += 1
            if color != '.':
                fill = '#%02x%02x%02x' % PALETTE[color][:3]
                rectangles.append(
                    f'  <rect x="{x}" y="{y}" width="{end - x}" height="1" fill="{fill}"/>')
            x = end
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" '
            'width="256" height="256" shape-rendering="crispEdges" '
            'role="img" aria-labelledby="title">\n'
            '  <title id="title">КРОТ — крот в защитных очках</title>\n'
            + '\n'.join(rectangles) + '\n</svg>\n').encode('utf-8')


def ico():
    images = [png(size) for size in SIZES]
    offset = 6 + 16 * len(images)
    entries = []
    for size, data in zip(SIZES, images):
        entries.append(struct.pack('<4B2H2I', size % 256, size % 256,
                                   0, 0, 1, 32, len(data), offset))
        offset += len(data)
    return struct.pack('<3H', 0, 1, len(images)) + b''.join(entries + images)


def validate_png(data, size):
    assert data.startswith(b'\x89PNG\r\n\x1a\n'), 'Invalid PNG signature'
    offset, compressed, kinds = 8, b'', []
    while offset < len(data):
        length, = struct.unpack_from('>I', data, offset)
        kind = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        end = offset + 12 + length
        assert end <= len(data), 'PNG chunk exceeds file bounds'
        assert zlib.crc32(kind + payload) == struct.unpack_from(
            '>I', data, offset + 8 + length)[0], 'PNG CRC mismatch'
        if kind == b'IHDR':
            assert struct.unpack('>2I5B', payload) == (size, size, 8, 6, 0, 0, 0)
        elif kind == b'IDAT':
            compressed += payload
        kinds.append(kind)
        offset = end
    assert kinds == [b'IHDR', b'IDAT', b'IEND'], 'Unexpected PNG structure'
    raw = zlib.decompress(compressed)
    assert len(raw) == size * (size * 4 + 1), 'Invalid PNG pixel count'
    assert all(raw[y * (size * 4 + 1)] == 0 for y in range(size)), 'Invalid PNG filter'
    assert raw[1:5] == bytes(4), 'Icon background must be transparent'


def validate_ico(data):
    assert struct.unpack_from('<3H', data) == (0, 1, len(SIZES)), 'Invalid ICO header'
    next_offset = 6 + len(SIZES) * 16
    for index, size in enumerate(SIZES):
        width, height, colors, reserved, planes, depth, length, offset = (
            struct.unpack_from('<4B2H2I', data, 6 + index * 16))
        assert (width or 256, height or 256) == (size, size), 'Invalid ICO dimensions'
        assert (colors, reserved, planes, depth) == (0, 0, 1, 32), 'Invalid ICO format'
        assert offset == next_offset and length > 0, 'ICO images overlap or leave gaps'
        assert offset + length <= len(data), 'ICO image exceeds file bounds'
        validate_png(data[offset:offset + length], size)
        next_offset += length
    assert next_offset == len(data), 'ICO has trailing data'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='validate without writing files')
    args = parser.parse_args()
    assets = {'krot.svg': svg(), 'krot.png': png(256),
              'krot-tray.png': png(32), 'krot.ico': ico()}
    validate_png(assets['krot.png'], 256)
    validate_png(assets['krot-tray.png'], 32)
    validate_ico(assets['krot.ico'])
    for name, content in assets.items():
        path = ROOT / 'assets' / name
        if args.check:
            assert path.read_bytes() == content, f'{path} is out of date; run scripts/build_icons.py'
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
    print('Icon assets checked.' if args.check else 'Icon assets generated.')


if __name__ == '__main__':
    main()
