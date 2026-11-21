"""Generate the media mascot SVGs: the icon's helmet and goggles with a snout and emotions."""
import argparse
from pathlib import Path

from build_icons import ART, PALETTE


ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'assets' / 'mascot'
COLORS = {code: '#%02x%02x%02x' % rgba[:3] for code, rgba in PALETTE.items() if code != '.'}
COLORS.update({
    'W': '#6e6a5c',  # dimmed lamp
    'b': '#6b5a50',  # fur
    'p': '#f0a0b0',  # nose and paws
    'n': '#b85f76',  # nostrils and mouth
    'c': '#f1efe9',  # claws
    'k': '#ffc400',  # ledge
    'K': '#c79500',  # ledge shade
    'r': '#ff5a36',  # error pupils
})

LENSES = (4, 10)
# The icon's head without its bottom outline, with empty lenses: pupils are drawn per emotion.
HEAD = [''.join('l' if 7 < y < 12 and any(lens - 1 <= x <= lens + 2 for lens in LENSES)
                else ch for x, ch in enumerate(row))
        for y, row in enumerate(ART[1:13], start=1)]
SNOUT = ['..obbbppppbbbo..', '..obbbpnnpbbbo..']
CHIN = '....oooooooo....'
MOUTH = {
    'neutral': '...obbbbbbbbo...',
    'sly': '...obbbbbnnbo...',
    'open': '...obbbnnbbbo...',
    'grin': '...obbnnnnbbo...',
}
RAYS = ((7, -3), (8, -3), (7, -2), (8, -2), (4, -2), (11, -2), (2, -1), (13, -1))
ZZZ = ((13, 0), (14, 0), (15, 0), (16, 0), (15, 1), (14, 2), (13, 3), (14, 3), (15, 3), (16, 3))

EMOTIONS = {
    'hello': ('привет', {}),
    'sly': ('хитрый', {'mouth': 'sly', 'look': 1, 'lid': True}),
    'surprised': ('удивлён', {'mouth': 'open', 'small': True}),
    'happy': ('радость', {'mouth': 'grin', 'arc': True, 'rays': True}),
    'sleepy': ('спит', {'lamp': 'W', 'closed': True, 'zzz': True}),
    'error': ('ошибка', {'mouth': 'open', 'pupil': 'r', 'up': 1, 'lamp': 'W'}),
}


def blank(width, height):
    return [['.'] * width for _ in range(height)]


def stamp(grid, rows, ox, oy):
    for y, row in enumerate(rows):
        for x, ch in enumerate(row):
            if ch != '.':
                grid[oy + y][ox + x] = ch


def eyes(grid, ox, oy, look=0, small=False, closed=False, arc=False, lid=False,
         pupil='y', up=0):
    for lens in LENSES:
        x, y = ox + lens + look, oy + 8 + up
        if lid:
            for dx in range(-1, 3):
                grid[oy + 7][ox + lens + dx] = 'g'
        if closed:
            for dx, dy in ((-1, 0), (0, 1), (1, 1), (2, 0)):
                grid[y + dy][x + dx] = 'f'
        elif arc:
            for dx, dy in ((-1, 1), (0, 0), (1, 0), (2, 1)):
                grid[y + dy][x + dx] = pupil
        elif small:
            grid[y][x] = pupil
        else:
            for dx, dy in ((0, 0), (1, 0), (0, 1), (1, 1)):
                grid[y + dy][x + dx] = pupil
            grid[y][x] = 'f'


def head(grid, ox, oy, mouth='neutral', lamp='w', rays=False, **eye):
    rows = HEAD + SNOUT + [MOUTH[mouth], CHIN]
    stamp(grid, [row.replace('w', lamp) for row in rows], ox, oy)
    eyes(grid, ox, oy, **eye)
    if rays:
        for x, y in RAYS:
            grid[oy + y][ox + x] = 'w'


def ledge():
    grid = blank(20, 23)
    head(grid, 2, 3, look=1, rays=True)
    stamp(grid, [
        '..opppobbbbbbopppo..',
        '..cpcpcoooooocpcpc..',
        'kkkkkkkkkkkkkkkkkkkk',
        'KKKKKKKKKKKKKKKKKKKK',
    ], 0, 17)
    return grid


def face(options):
    options = dict(options)
    zzz = options.pop('zzz', False)
    grid = blank(18, 20)
    head(grid, 1, 4, **options)
    if zzz:
        for x, y in ZZZ:
            grid[y][x] = 'f'
    return grid


def svg(grid, title):
    height, width = len(grid), len(grid[0])
    rectangles = []
    for y, row in enumerate(grid):
        x = 0
        while x < width:
            end = x + 1
            while end < width and row[end] == row[x]:
                end += 1
            if row[x] != '.':
                rectangles.append(f'  <rect x="{x}" y="{y}" width="{end - x}" height="1" '
                                  f'fill="{COLORS[row[x]]}"/>')
            x = end
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="{width * 16}" height="{height * 16}" shape-rendering="crispEdges" '
            'role="img" aria-labelledby="title">\n'
            f'  <title id="title">{title}</title>\n'
            + '\n'.join(rectangles) + '\n</svg>\n').encode('utf-8')


def assets():
    result = {'krot-ledge.svg': svg(ledge(), 'КРОТ выглядывает из-за края')}
    for key, (name, options) in EMOTIONS.items():
        result[f'krot-face-{key}.svg'] = svg(face(options), f'КРОТ: {name}')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='validate without writing files')
    args = parser.parse_args()
    generated = assets()
    if args.check:
        for name, content in generated.items():
            path = OUT / name
            assert path.read_bytes() == content, f'{path} is out of date; run scripts/build_mascot.py'
        extra = {path.name for path in OUT.glob('*.svg')} - set(generated)
        assert not extra, f'Unexpected mascot files: {sorted(extra)}'
    else:
        OUT.mkdir(parents=True, exist_ok=True)
        for name, content in generated.items():
            (OUT / name).write_bytes(content)
    print('Mascot assets checked.' if args.check else 'Mascot assets generated.')


if __name__ == '__main__':
    main()
