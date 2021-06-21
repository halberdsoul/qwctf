import sys
from hashlib import sha256
import dis

def KSA(key):
    """ This initialises the permutation in array S."""
    keylength = len(key)
    # 256 is the max keylength
    S = list(range(256))
    j=0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        # swap values of S[i] and S[j]
        S[i], S[j] = S[j], S[i] # swap

    return S

def PRGA(S):
    """Initialsises the pseudo-random generator, which takes in values of S"""
    Klist =[] 
    i=0
    j=0
    while True:
        # increments i, and looks up the ith element of S, S[i]
        i =(i+1)%256
        # which it then adds to j
        j =(j+S[i])%256
        # swaps again
        S[i], S[j] = S[j], S[i] # swap
        # use the sum S[i] + S[j] mod 256 as an index to find a third element of S
        K = S[(S[i] + S[j]) % 256]
        # like return, but for generator functions
        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)

def xor(p, stream):
    return ''.join(map((lambda x: chr(x ^ stream.__next__())), p))

def a():
    b = b'geo'
    return ((i,i) for i in b)

if __name__ == '__main__': 
    dis.dis(a)
    exit()
    w = b'\xf6\xef\x10H\xa9\x0f\x9f\xb5\x80\xc1xd\xae\xd3\x03\xb2\x84\xc2\xb4\x0e\xc8\xf3<\x151\x19\n\x8f'
    e = b'$\r9\xa3\x18\xddW\xc9\x97\xf3\xa7\xa8R~' 
    b= b'geo'
    s = b'}\xce`\xbej\xa2\x120\xb5\x8a\x94\x14{\xa3\x86\xc8\xc7\x01\x98\xa3_\x91\xd8\x82T*V\xab\xe0\xa1\x141'
    t = b"Q_\xe2\xf8\x8c\x11M}'<@\xceT\xf6?_m\xa4\xf8\xb4\xea\xca\xc7:\xb9\xe6\x06\x8b\xeb\xfabH\x85xJ3$\xdd\xde\xb6\xdc\xa0\xb8b\x961\xb7\x13=\x17\x13\xb1"

    # m = {
    #     2: 115,
    #     8: 97,
    #     11: 117,
    #     10: 114}
    # n = {
    #     3: 119,
    #     7: 116,
    #     9: 124,
    #     12: 127}
    # 这两行是关键，咋撸出来的？
    # {x:n[x]^x for x in n}
    # {5:103, 4: 101, 6: 111}
    
    m = {
        2: 115,
        8: 97,
        11: 117,
        10: 114, 5: 103, 4: 101, 6: 111, 3: 116, 7: 115, 9: 117, 12: 115}

    stream = RC4(list(map((lambda x: x[1]), sorted(m.items())))) 
    print(xor(w, stream))
    # p = sys.stdin.buffer.read()
    p = b'\xe5\n2\xd6"\xf0}I\xb0\xcd\xa2\x11\xf0\xb4U\x166\xc5o\xdb\xc9\xead\x04\x15b'
    e = xor(e, stream)
    c = xor(p, stream)
    print(c)
    print(xor(t, stream))

    # if sha256(c).digest() == s:
    #     print(xor(t, stream).decode())
    #     return None
    # None(e.decode())
    # return None