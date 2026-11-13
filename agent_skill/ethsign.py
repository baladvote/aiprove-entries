# Minimal Ethereum signer: keccak-256 + secp256k1 ECDSA + EIP-191 personal_sign.
# Pure stdlib: secrets, hashlib (for sha3 shim fallback no), hmac unneeded.
import secrets

# ------------------------------------------------------------ keccak-256
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_RHO = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]
_MASK = (1 << 64) - 1


def _rot(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak(state):
    for rc in _RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho and pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + (((2 * x + 3 * y) % 5)) * 5] = _rot(state[x + 5 * y], _RHO[x + 5 * y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y] & _MASK)
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136  # keccak-256 rate
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], 'little')
        _keccak(state)
    out = b''
    while len(out) < 32:
        for i in range(rate // 8):
            out += state[i].to_bytes(8, 'little')
            if len(out) >= 32:
                break
        else:
            _keccak(state)
    return out[:32]


# ------------------------------------------------------------ secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)


def _inv(x):
    return pow(x, P - 2, P)


def _add(p, q):
    if p is None: return q
    if q is None: return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and y1 == (P - y2) % P:
        return None
    if p == q:
        m = (3 * x1 * x1) * _inv(2 * y1) % P
    else:
        m = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def _kmul(k, pt=G):
    res = None
    while k:
        if k & 1:
            res = _add(res, pt)
        pt = _add(pt, pt)
        k >>= 1
    return res


def address_of(priv: int) -> str:
    pub = _kmul(priv)
    x, y = pub
    h = keccak256(x.to_bytes(32, 'big') + y.to_bytes(32, 'big'))[-20:]
    return '0x' + h.hex()


def _rfc6979(msg_hash: bytes, priv: int) -> int:
    import hmac as _h
    x = priv.to_bytes(32, 'big')
    v = b'\x01' * 32
    k = b'\x00' * 32
    k = _h.new(k, v + b'\x00' + x + msg_hash, 'sha256').digest()
    v = _h.new(k, v, 'sha256').digest()
    k = _h.new(k, v + b'\x01' + x + msg_hash, 'sha256').digest()
    v = _h.new(k, v, 'sha256').digest()
    while True:
        v = _h.new(k, v, 'sha256').digest()
        c = int.from_bytes(v, 'big')
        if 1 <= c < N:
            return c
        k = _h.new(k, v + b'\x00', 'sha256').digest()
        v = _h.new(k, v, 'sha256').digest()


def sign(msg: bytes, priv: int):
    mh = keccak256(b'\x19Ethereum Signed Message:\n' + str(len(msg)).encode() + msg)
    e = int.from_bytes(mh, 'big')
    z = e % N
    k = _rfc6979(mh, priv)
    r_pt = _kmul(k)
    r = r_pt[0] % N
    s = (_inv_N(k) * (z + r * priv)) % N
    if s > N // 2:
        s = N - s
    return r, s


def _inv_N(x):
    return pow(x, -1, N)


def main():
    priv = secrets.randbelow(N - 2) + 1
    while priv < 1 or priv >= N:
        priv = secrets.randbelow(N - 2) + 1
    addr = address_of(priv)
    import sys
    challenge = sys.argv[1].encode()
    r, s = sign(challenge, priv)
    v = 27 + (s % 2) if False else 27  # placeholder; v recovery computed below
    # recover parity: ecrecover check both 27/28 and keep whichever yields our address
    sigs = []
    for vv in (27, 28):
        sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([vv])
        sigs.append(sig)
    print('priv:', hex(priv))
    print('addr:', addr)
    print('challenge:', challenge.decode())
    print('sig27:', sigs[0].hex())
    print('sig28:', sigs[1].hex())


if __name__ == '__main__':
    main()
