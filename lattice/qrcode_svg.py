"""Pure-Python zero-dependency ISO/IEC 18004 QR Code (Byte mode, ECC Level L, Versions 1-6) SVG generator."""
from __future__ import annotations

_VERSION_TABLE = {
    1: (21, 26, 7, 1, 17),
    2: (25, 44, 10, 1, 32),
    3: (29, 70, 15, 1, 53),
    4: (33, 100, 20, 1, 78),
    5: (37, 134, 26, 1, 106),
    6: (41, 172, 18, 2, 134),
}

_ALIGNMENT_POS = {
    1: [],
    2: [6, 18],
    3: [6, 22],
    4: [6, 26],
    5: [6, 30],
    6: [6, 34],
}

_FORMAT_BITS_L_MASK0 = 0x77C4

_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator_poly(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        nxt = [0] * (len(poly) + 1)
        root = _GF_EXP[i]
        for j, coeff in enumerate(poly):
            nxt[j] ^= coeff
            nxt[j + 1] ^= _gf_mul(coeff, root)
        poly = nxt
    return poly


def _rs_encode(data: list[int], ec_len: int) -> list[int]:
    gen = _rs_generator_poly(ec_len)
    reg = [0] * ec_len
    for byte in data:
        factor = byte ^ reg[0]
        reg = reg[1:] + [0]
        if factor:
            for j in range(ec_len):
                reg[j] ^= _gf_mul(gen[j + 1], factor)
    return reg


def _encode_data_codewords(payload: bytes, ver: int) -> list[int]:
    _, total_cw, ec_cw, blocks, _ = _VERSION_TABLE[ver]
    data_cw = total_cw - ec_cw * blocks
    bits: list[int] = []

    def push_bits(val: int, length: int) -> None:
        for i in range(length - 1, -1, -1):
            bits.append((val >> i) & 1)

    push_bits(0b0100, 4)
    push_bits(len(payload), 8)
    for b in payload:
        push_bits(b, 8)

    max_bits = data_cw * 8
    term = min(4, max_bits - len(bits))
    push_bits(0, term)
    while len(bits) % 8 != 0:
        bits.append(0)

    codewords = [int("".join(str(bit) for bit in bits[i : i + 8]), 2) for i in range(0, len(bits), 8)]
    pad_bytes = (0xEC, 0x11)
    idx = 0
    while len(codewords) < data_cw:
        codewords.append(pad_bytes[idx % 2])
        idx += 1

    if blocks == 1:
        return codewords + _rs_encode(codewords, ec_cw)

    block_size = data_cw // blocks
    data_blocks = [codewords[i * block_size : (i + 1) * block_size] for i in range(blocks)]
    ec_blocks = [_rs_encode(blk, ec_cw) for blk in data_blocks]
    interleaved: list[int] = []
    for col in range(block_size):
        for b in range(blocks):
            interleaved.append(data_blocks[b][col])
    for col in range(ec_cw):
        for b in range(blocks):
            interleaved.append(ec_blocks[b][col])
    return interleaved


def generate_qr_svg(text: str, box_size: int = 5, border: int = 2) -> str:
    """Generate a standalone, crisp SVG QR code for a URL or hostname."""
    raw = text.strip().encode("utf-8")[:134]
    ver = 1
    for v, spec in _VERSION_TABLE.items():
        if len(raw) <= spec[4]:
            ver = v
            break
    else:
        ver = 6
        raw = raw[: _VERSION_TABLE[6][4]]

    size = _VERSION_TABLE[ver][0]
    matrix: list[list[int | None]] = [[None] * size for _ in range(size)]
    reserved: list[list[bool]] = [[False] * size for _ in range(size)]

    def set_mod(r: int, c: int, val: int, res: bool = True) -> None:
        if 0 <= r < size and 0 <= c < size:
            matrix[r][c] = int(bool(val))
            if res:
                reserved[r][c] = True

    def place_finder(row: int, col: int) -> None:
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = row + dr, col + dc
                if 0 <= r < size and 0 <= c < size:
                    in_outer = 0 <= dr <= 6 and 0 <= dc <= 6 and (dr in (0, 6) or dc in (0, 6))
                    in_inner = 2 <= dr <= 4 and 2 <= dc <= 4
                    set_mod(r, c, 1 if (in_outer or in_inner) else 0, True)

    place_finder(0, 0)
    place_finder(0, size - 7)
    place_finder(size - 7, 0)

    align = _ALIGNMENT_POS[ver]
    for ar in align:
        for ac in align:
            if (ar < 8 and ac < 8) or (ar < 8 and ac > size - 9) or (ar > size - 9 and ac < 8):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    val = 1 if (abs(dr) == 2 or abs(dc) == 2 or (dr == 0 and dc == 0)) else 0
                    set_mod(ar + dr, ac + dc, val, True)

    for i in range(8, size - 8):
        set_mod(6, i, 1 if i % 2 == 0 else 0, True)
        set_mod(i, 6, 1 if i % 2 == 0 else 0, True)

    set_mod(size - 8, 8, 1, True)

    for i in range(9):
        if i != 6:
            reserved[8][i] = True
            reserved[i][8] = True
    for i in range(8):
        reserved[8][size - 1 - i] = True
        reserved[size - 1 - i][8] = True

    codewords = _encode_data_codewords(raw, ver)
    bit_stream: list[int] = []
    for cw in codewords:
        for b in range(7, -1, -1):
            bit_stream.append((cw >> b) & 1)

    bit_idx = 0
    up = True
    col = size - 1
    while col > 0:
        if col == 6:
            col -= 1
        row_iter = range(size - 1, -1, -1) if up else range(size)
        for row in row_iter:
            for dc in (0, -1):
                c = col + dc
                if not reserved[row][c]:
                    bit = bit_stream[bit_idx] if bit_idx < len(bit_stream) else 0
                    bit_idx += 1
                    if (row + c) % 2 == 0:
                        bit ^= 1
                    matrix[row][c] = bit
        up = not up
        col -= 2

    fmt = _FORMAT_BITS_L_MASK0
    fmt_bits = [(fmt >> i) & 1 for i in range(15)]
    coords_tl = [
        (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
        (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8),
    ]
    for idx, (r, c) in enumerate(coords_tl):
        matrix[r][c] = fmt_bits[14 - idx]
    for idx in range(7):
        matrix[size - 1 - idx][8] = fmt_bits[14 - idx]
    for idx in range(7, 15):
        matrix[8][size - 15 + idx] = fmt_bits[14 - idx]

    dim = (size + border * 2) * box_size
    rects: list[str] = []
    for r in range(size):
        for c in range(size):
            if matrix[r][c]:
                x = (c + border) * box_size
                y = (r + border) * box_size
                rects.append(f'<rect x="{x}" y="{y}" width="{box_size}" height="{box_size}"/>')

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" width="{dim}" height="{dim}" '
        f'shape-rendering="crispEdges" role="img" aria-label="Provisioning QR Code">'
        f'<rect width="{dim}" height="{dim}" rx="8" fill="#ffffff"/>'
        f'<g fill="#080c10">{"".join(rects)}</g>'
        f"</svg>"
    )
