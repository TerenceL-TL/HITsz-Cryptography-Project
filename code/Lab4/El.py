import random
from hashlib import sha256

def mod_inv(a, p):
    return pow(a, p-2, p)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

class ElGamalSignature:
    def __init__(self, p, g, x):
        self.p = p  # 大质数 p
        self.g = g  # 基数 g
        self.x = x  # 私钥 x
        self.y = pow(g, x, p)  # 公钥 y = g^x mod p
    
    def get_public_key(self):
        return self.y

    # 计算消息 m 的哈希值
    def hash_message(self, m):
        return int(sha256(m.encode()).hexdigest(), 16)  # 将消息哈希转为整数
    
    # 签名生成
    def sign(self, m):
        k = random.randint(1, self.p - 1)  # 随机选择 k
        while gcd(k, self.p - 1) != 1:  # k 必须与 p-1 互质
            k = random.randint(1, self.p - 1)
        
        r = pow(self.g, k, self.p)  # r = g^k mod p
        Hm = self.hash_message(m)
        s = (mod_inv(k, self.p - 1) * (Hm - self.x * r)) % (self.p - 1)  # s = k^-1 * (H(m) - x * r) mod (p-1)
        return r, s, k
    
    # 签名验证
    def verify(self, m, r, s, y):
        if r <= 0 or r >= self.p:
            return False  # r 不合法
        if s <= 0 or s >= self.p - 1:
            return False  # s 不合法

        # 验证签名
        print("Ving")
        Hm = self.hash_message(m)
        lhs = ((pow(y, r, p) % p) * (pow(r, s, p) % p)) % self.p
        rhs = pow(self.g, Hm, p)

        print("Lhs =",lhs);
        print("Rhs =",rhs);
        return lhs == rhs

p = 7919  # 质数 p
g = 6977     # 基 g
x = random.randint(1, p - 1)  # 私钥 x

elgamal = ElGamalSignature(p, g, x)

y = elgamal.get_public_key()

# 用学号作为消息 m
m = '220110609'  

# 签名生成过程，随机生成两次不同的 k
r1, s1, k1 = elgamal.sign(m)
r2, s2, k2 = elgamal.sign(m)

# 输出结果
print(f"公钥 (p, g, y): ({p}, {g}, {elgamal.y})")
print(f"私钥 x: {x}")
print(f"第一个随机数 k: {k1}")
print(f"第二个随机数 k: {k2}")
print(f"签名1: r1 = {r1}, s1 = {s1}")
print(f"签名2: r2 = {r2}, s2 = {s2}")

# 验证签名
valid1 = elgamal.verify(m, r1, s1, y)
valid2 = elgamal.verify(m, r2, s2, y)

print(f"第一个签名验证结果: {'通过' if valid1 else '不通过'}")
print(f"第二个签名验证结果: {'通过' if valid2 else '不通过'}")

# 假设消息被篡改
m_tampered = '220110610'  # 篡改后的消息

valid_tampered = elgamal.verify(m_tampered, r1, s1, y)
print(f"篡改后的消息签名验证结果: {'通过' if valid_tampered else '不通过'}")
