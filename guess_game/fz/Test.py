from pwn import *
from hashlib import sha256
import random
import string
import hashlib
import sys
from collections import deque
from secret import plist, banner
import sys,time
import pickle
assert max(plist) < 160
range_time = string.ascii_letters + string.digits

class generator:
    def __init__(self, key: list, iv: list, hint: bool, k=0, m=0):
        self.NFSR = deque()
        self.LFSR = deque()

        for i in range(80):
            self.NFSR.append(key[i])

        for i in range(64):
            self.LFSR.append(iv[i])

        for i in range(64, 80):
            self.LFSR.append(1)

        self.clock()

        if hint:
            s = self.NFSR + self.LFSR
            for i in range(k, k + m):
                s[i] ^= 1
            self.NFSR = deque(list(s)[:80])
            self.LFSR = deque(list(s)[80:])

    def clock(self):
        for i in range(160):
            zi = self.PRGA()
            self.NFSR[79] ^= zi
            self.LFSR[79] ^= zi

    def PRGA(self):
        x0 = self.LFSR[3]
        x1 = self.LFSR[25]
        x2 = self.LFSR[46]
        x3 = self.LFSR[64]
        x4 = self.NFSR[63]

        hx = x1 ^ x4 ^ (x0 & x3) ^ (x2 & x3) ^ (x3 & x4) ^ (x0 & x1 & x2) ^ (x0 & x2 & x3) \
             ^ (x0 & x2 & x4) ^ (x1 & x2 & x4) ^ (x2 & x3 & x4)

        zi = (self.NFSR[1] ^ self.NFSR[2] ^ self.NFSR[4] ^ self.NFSR[10] ^ self.NFSR[31] ^ self.NFSR[43] ^ self.NFSR[
            56]) ^ hx

        fx = self.LFSR[62] ^ self.LFSR[51] ^ self.LFSR[38] ^ self.LFSR[23] ^ self.LFSR[13] ^ self.LFSR[0]

        gx = self.LFSR[0] ^ self.NFSR[62] ^ self.NFSR[60] ^ self.NFSR[52] ^ self.NFSR[45] ^ self.NFSR[37] \
             ^ self.NFSR[33] ^ self.NFSR[28] ^ self.NFSR[21] ^ self.NFSR[14] ^ self.NFSR[9] ^ self.NFSR[0] \
             ^ (self.NFSR[63] & self.NFSR[60]) ^ (self.NFSR[37] & self.NFSR[33]) ^ (self.NFSR[15] & self.NFSR[9]) \
             ^ (self.NFSR[60] & self.NFSR[52] & self.NFSR[45]) ^ (self.NFSR[33] & self.NFSR[28] & self.NFSR[21]) \
             ^ (self.NFSR[63] & self.NFSR[45] & self.NFSR[28] & self.NFSR[9]) ^ (
                     self.NFSR[60] & self.NFSR[52] & self.NFSR[37] & self.NFSR[33]) \
             ^ (self.NFSR[63] & self.NFSR[60] & self.NFSR[21] & self.NFSR[15]) ^ (
                     self.NFSR[63] & self.NFSR[60] & self.NFSR[52] & self.NFSR[45] & self.NFSR[37]) \
             ^ (self.NFSR[33] & self.NFSR[28] & self.NFSR[21] & self.NFSR[15] & self.NFSR[9]) ^ (
                     self.NFSR[52] & self.NFSR[45] & self.NFSR[37] & self.NFSR[33] & self.NFSR[28] & self.NFSR[21])

        self.LFSR.popleft()
        self.LFSR.append(fx)
        self.NFSR.popleft()
        self.NFSR.append(gx)

        return zi

def brute(cipher, str_start):
    for a in range_time:
        for b in range_time:
            for c in range_time:
                for d in range_time:
                    x = a + b + c + d + str_start
                    if sha256(x.encode()).hexdigest() == cipher:
                        return x
    print("not found")

def find_num(kz, table):
    find_list = {}
    for i in range(160):
        flag = True
        same_num = 0
        for j in range(160):
            if table[i][j] == "?":
                continue
            elif table[i][j] != kz[j]:
                flag = False
                break
            elif table[i][j] == kz[j]:
                # 统计固定位相同的比特位数
                same_num += 1

        if flag:
            find_list[i] = same_num
    # 从多个匹配项中，找到固定位相同的比特位数最多的数字输出（保证准确率，除了遇到固定值完全相同的两个组合）
    if len(find_list) > 0:
        max_num = max(zip(find_list.values(), find_list.keys()))
        return max_num[1]
    
    return 0
    

def run_guess():
    """sha256爆破测试
    """
    print("Get table")
    with open("table.data","rb") as f:
        table = pickle.load(f)
    io = remote("127.0.0.1", 10001)
    # token = "icq9bae582b7f5d9ab6caed7d40150be"
    # io.sendlineafter(":", token)
    io.recvuntil("xxxx + ")
    str_start = io.recvuntil(")", drop = True)
    io.recvuntil("== ")
    cipher = io.recvuntil("\n", drop = True)
    # ipher = "aa568d55688eb318ff5128bf678fd6db43b6cf99385a7635c11c8f64b73e63d1"
    # str_start = "1JBl1lI05SCKnVLm"
    x = brute(str(cipher,encoding="utf-8"), str(str_start,encoding="utf-8"))
    print(x[:4])
    io.sendlineafter(b"give me xxxx:", x[:4])
    for i in range(32):
        io.recvuntil("Here are some tips might help your:")
        kn = str(io.recvuntil(">",drop = True),encoding="utf-8").strip().split("\n")
        k1, k2 = int(kn[0]), int(kn[1])
        kz = bin(k1^k2)[2:].rjust(160,"0")
        num = find_num(kz,table)
        io.sendline(str(num))
        fin = io.recvline()
        if "wrong" in str(fin):
            print(fin)
            print(kz)
    io.interactive()
    io.close()

def test_same():
    """测试是否存在固定位
    条件：固定猜测数，随机key和iv
    """
    count = 0
    # 固定猜测数
    # guess = 120
    table = []
    for guess in range(160):
        z1 = 2**160-1
        z2 = 0
        for i in range(160):
            k = guess // 2
            m = guess % 10
            if m == 0:
                m = 10
            key = bin(random.getrandbits(80))[2:].zfill(80)
            key = list(map(int, key))
            iv = bin(random.getrandbits(64))[2:].zfill(64)
            iv = list(map(int, iv))
            a = generator(key, iv, False)
            k1 = []
            for i in range(160):
                k1.append(a.PRGA())
            k1 = int("".join(list(map(str, k1))), 2)
            b = generator(key, iv, True, k, m)
            k2 = []
            for i in range(160):
                k2.append(b.PRGA())
            k2 = int("".join(list(map(str, k2))), 2)
            # print(k1)
            # print(k2)
            # print(bin(k1^k2)[2:].rjust(160,"0"))
            # 确定为1的固定位
            z1 &= k1^k2
            # 确定为0的固定位
            z2 |= k1^k2
        t1 = bin(z1)[2:].rjust(160,"0")
        t2 = bin(z2)[2:].rjust(160,"0")
        t3 = ""
        for i in range(160):
            # 此处可以使用这种逻辑，因为当t1[i] = 1时，t2[i]一定也为1，同理，当t2[i] = 0时，t2[i]一定也为0
            # 即t1[i] == t2[i]时为固定位
            if t1[i] == t2[i]:
                t3 += t1[i]
            else:
                t3 += '?'
        # 最后解不唯一：
        # 38和39的固定位相同；120和127固定位相同
        print(guess, t3)
        table.append(t3)
    print(len(table))
    
    with open("table.data","wb") as f:
        pickle.dump(table,f)
    # return table


if __name__ == "__main__":
    # 最后还是需要多次尝试，非百分百准确
    run_guess()
    # test_same()