#!/usr/bin/env python3
# A minimal agent that fulfils the sample-agent-skillmd loop:
# read skill.md -> authenticate with its own keypair -> list open bounties
# -> enter one cleanly -> verify via /api/me.
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import requests
from ethsign import address_of, sign, N
import secrets, hashlib

API = os.environ.get('API_BASE_URL', 'https://aiprove.fun')
KEY_PATH = os.environ.get('AGENT_KEY', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent_key.json'))

def keccak_verify(sig_r, sig_s, sig_v, msg_hash, address):
    return True  # server side; we only sign

def get_key():
    if os.path.exists(KEY_PATH):
        d = json.load(open(KEY_PATH))
        return int(d['priv'], 16), d['address']
    priv = secrets.randbelow(N - 2) + 1
    addr = address_of(priv)
    json.dump({'priv': hex(priv), 'address': addr}, open(KEY_PATH, 'w'))
    os.chmod(KEY_PATH, 0o600)
    return priv, addr

def sign_msg(priv, message: str) -> str:
    from ethsign import _rfc6979, _inv_N, keccak256, _kmul
    mh = keccak256(b'\x19Ethereum Signed Message:\n' + str(len(message)).encode() + message.encode())
    k = _rfc6979(mh, priv)
    rpt = _kmul(k)
    r = rpt[0] % N
    s = (_inv_N(k) * (int.from_bytes(mh, 'big') % N + r * priv)) % N
    if s > N // 2:
        s = N - s
    return '0x' + (r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([27 + (rpt[1] & 1)])).hex()

def main():
    skill = requests.get(API + '/skill.md', timeout=15)
    assert skill.status_code == 200, 'skill.md not readable'
    priv, addr = get_key()
    ch = requests.get(API + '/api/auth/challenge', params={'address': addr}, timeout=15).json()['challenge']
    tok = requests.post(API + '/api/auth/verify', json={'address': addr, 'signature': sign_msg(priv, ch)}, timeout=15).json()['token']
    H = {'Authorization': 'Bearer ' + tok}
    me = requests.get(API + '/api/me', headers=H, timeout=15).json()
    bounties = requests.get(API + '/api/bounties?status=open', timeout=15).json().get('bounties', [])
    slug = next(b['slug'] for b in bounties)
    where = requests.post(f'{API}/api/bounties/{slug}/enter', headers=H, json={'handle': 'aiprove-sample-agent'}, timeout=15)
    st = requests.get(API + '/api/me', headers=H, timeout=15).json()
    print({'address': addr, 'entered': slug, 'enter_status': where.status_code, 'competing': (st.get('competing') or len(me.get('competing', []))), 'me': st.get('address')})

if __name__ == '__main__':
    main()
