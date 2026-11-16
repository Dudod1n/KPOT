"""Generate the pixel mole SVG, PNGs and Windows ICO using only Python's stdlib."""
import argparse
from pathlib import Path
import struct
import zlib


ROOT = Path(__file__).resolve().parent.parent
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
PALETTE = {
    '.': (0, 0, 0, 0),
    'o': (16, 17, 19, 255),
    'y': (255, 196, 0, 255),
    'd': (199, 149, 0, 255),
    'g': (58, 61, 66, 255),
    'w': (255, 246, 208, 255),
    'f': (241, 239, 233, 255),
    'l': (23, 24, 26, 255),
    's': (90, 94, 100, 255),
}

# Mole in a miner's helmet with a lamp and goggles, as in the "Stroyka" theme.
ART = (
    '................',
    '.....oooooo.....',
    '....oyyggyyo....',
    '...oyygwwgyyo...',
    '..oyyygwwgyyyo..',
    '..odddggggdddo..',
    'oyyyyyyyyyyyyyyo',
    '.offffffffffffo.',
    '.ofllllffllllfo.',
    'soflfylfflfylfos',
    'soflyylfflyylfos',
    '.ofllllffllllfo.',
    '.offffffffffffo.',
    '..oooooooooooo..',
    '................',
    '................',
)


def sprite():
    assert len(ART) == 16 and all(len(row) == 16 for row in ART), 'Icon art must be 16x16'
    return [list(row) for row in ART]


PIXELS = sprite()


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack(
        '>I', zlib.crc32(kind + data))


def scanlines(size):
    return b''.join(b'\0' + b''.join(
        bytes(PALETTE[PIXELS[y * 16 // size][x * 16 // size]])
        for x in range(size)) for y in range(size))


def png(size):
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack(
        '>2I5B', size, size, 8, 6, 0, 0, 0))
        + chunk(b'IDAT', zlib.compress(scanlines(size), 9)) + chunk(b'IEND', b''))


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
            '  <title id="title">КРОТ — крот в шахтёрской каске и очках</title>\n'
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
    assert raw == scanlines(size), 'Icon pixels are out of date'


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
            stored = path.read_bytes()
            if name.endswith('.png'):
                validate_png(stored, 256 if name == 'krot.png' else 32)
            elif name.endswith('.ico'):
                validate_ico(stored)
            else:
                assert stored == content, f'{path} is out of date; run scripts/build_icons.py'
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
    print('Icon assets checked.' if args.check else 'Icon assets generated.')


if __name__ == '__main__':
    main()
