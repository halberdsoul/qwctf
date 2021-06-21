'''
Author: your name
Date: 2021-06-13 01:58:03
LastEditTime: 2021-06-13 01:58:14
LastEditors: your name
Description: In User Settings Edit
FilePath: /附件/pcap_code.py
'''
# Source Generated with Decompyle++
# File: result.pyc (Python 3.8)

import sys
from hashlib import sha256

def KSA(key):
    keylength = len(key)
    S = list(range(256))
    j = 0
    return S


def PRGA(S):
Unsupported opcode: <255>
    pass
# WARNING: Decompyle incomplete


def RC4(key):
    S = KSA(key)
    return PRGA(S)


def xor(p, stream):
    return None(None((lambda x = None: x ^ stream.__next__()), p))

if __name__ == '__main__':
    w = b'\xf6\xef\x10H\xa9\x0f\x9f\xb5\x80\xc1xd\xae\xd3\x03\xb2\x84\xc2\xb4\x0e\xc8\xf3<\x151\x19\n\x8f'
    e = b'$\r9\xa3\x18\xddW\xc9\x97\xf3\xa7\xa8R~'
    b = b'geo'
    s = b'}\xce`\xbej\xa2\x120\xb5\x8a\x94\x14{\xa3\x86\xc8\xc7\x01\x98\xa3_\x91\xd8\x82T*V\xab\xe0\xa1\x141'
    t = b"Q_\xe2\xf8\x8c\x11M}'<@\xceT\xf6?_m\xa4\xf8\xb4\xea\xca\xc7:\xb9\xe6\x06\x8b\xeb\xfabH\x85xJ3$\xdd\xde\xb6\xdc\xa0\xb8b\x961\xb7\x13=\x17\x13\xb1"
    m = {
        2: 115,
        8: 97,
        11: 117,
        10: 114 }
    n = {
        3: 119,
        7: 116,
        9: 124,
        12: 127 }
# 下面的这个 |= 拼接方法在python3.9+中开始支持……
Unsupported opcode: MAP_ADD
    m |= (lambda .0: pass# WARNING: Decompyle incomplete
)(n)
Unsupported opcode: <255>
    m |= (lambda .0: pass# WARNING: Decompyle incomplete
)(b)
    stream = RC4(list(map((lambda x: x[1]), sorted(m.items()))))
    print(xor(w, stream).decode())
    p = sys.stdin.buffer.read()
    e = xor(e, stream)
    c = xor(p, stream)
    if sha256(c).digest() == s:
        print(xor(t, stream).decode())
        return None
    None(e.decode())
    return None