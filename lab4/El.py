import random
from hashlib import sha256

# 计算快速模幂
def mod_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# 计算扩展欧几里得算法
def exgcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = exgcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

# 密钥生成
def generate_keys():
    p = 104729 
    g = 78927  
    x = random.randint(2, p-2)  # 选择私钥 x
    y = mod_exp(g, x, p)  # 计算公钥 y
    return p, g, y, x

# 签名
def sign_message(m, p, g, x):
    k = random.randint(2, p-2)
    while gcd(k, p-1) != 1:
        k = random.randint(2, p-2)
    
    Hm = int(sha256(m.encode()).hexdigest(), 16)  # SHA256
    r = mod_exp(g, k, p)
    k_inv = exgcd(k, p-1)[1] % (p-1)
    s = (k_inv * (Hm - x * r)) % (p-1)
    return r, s, k

# 验证签名
def verify_signature(m, r, s, p, g, y):
    Hm = int(sha256(m.encode()).hexdigest(), 16)
    v1 = mod_exp(y, r, p) * mod_exp(r, s, p) % p
    v2 = mod_exp(g, Hm, p)
    return v1 == v2

# 测试
p, g, y, x = generate_keys()
m = "220110609"  # 使用学号作为消息
r1, s1, k1 = sign_message(m, p, g, x)
r2, s2, k2 = sign_message(m, p, g, x)

print(f"公钥: (p={p}, g={g}, y={y})")
print(f"私钥: x={x}")
print(f"信息: m={m}")
print(f"签名1: (r={r1}, s={s1}) 使用 k={k1}")
print(f"签名2: (r={r2}, s={s2}) 使用 k={k2}")
print(f"验证签名1: {verify_signature(m, r1, s1, p, g, y)}")
print(f"验证签名2: {verify_signature(m, r2, s2, p, g, y)}")

# 消息被篡改
m_modified = "213612333"
print(f"篡改信息: m={m_modified}")
print(f"验证篡改后的签名: {verify_signature(m_modified, r1, s1, p, g, y)}")
