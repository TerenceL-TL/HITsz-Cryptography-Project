import random
import time

def is_prime(n, k=10):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def mod_pow(b, exp, mod):
    res = 1
    b = b % mod

    while exp > 0:
        if (exp % 2) == 1:
            res = (res * b) % mod

        exp = exp // 2
        b = (b * b) % mod

    return res

def generate_keys():
    p = gen_prime(64)
    q = gen_prime(64)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = gen_prime(64)
    d = mod_inv(e, phi_n)

    return {
        'p': p,
        'q': q,
        'n': n,
        'e': e,
        'd': d,
        'phi(n)': phi_n
    }

def encrypt(plaintext, n, e):
    ciphertext = []
    start_time = time.time()
    
    for i in range(0, len(plaintext), 2):
        if i + 1 < len(plaintext):
            pair = plaintext[i:i + 2]
            m_group = ord(pair[0]) * 1000 + ord(pair[1])
            ciphertext.append(mod_pow(m_group, e, n))
        else:
            m_group = ord(plaintext[i]) * 1000
            ciphertext.append(mod_pow(m_group, e, n))
    
    end_time = time.time()
    encryption_time = end_time - start_time

    return ciphertext, encryption_time

def decrypt(ciphertext, n, d):
    decrypted = ''
    start_time = time.time()
    
    for num in ciphertext:
        decrypted_pair = mod_pow(num, d, n)
        dechar_1 = chr(decrypted_pair // 1000)
        dechar_2 = chr(decrypted_pair % 1000)
        decrypted += dechar_1 + dechar_2

    end_time = time.time()
    decryption_time = end_time - start_time

    return decrypted, decryption_time

# 从文件读取明文
with open('lab2-Plaintext.txt', 'r') as file:
    plaintext = file.read()

# 生成密钥
keys = generate_keys()

# 将公钥和私钥写入文件
with open('public_key.txt', 'w') as pub_file:
    pub_file.write(f"n: {keys['n']}\n")
    pub_file.write(f"e: {keys['e']}\n")

with open('private_key.txt', 'w') as priv_file:
    priv_file.write(f"d: {keys['d']}\n")

# 执行RSA加密
ciphertext, encryption_time = encrypt(plaintext, keys['n'], keys['e'])

# 将密文写入文件
with open('ciphertext.txt', 'w') as file:
    for num in ciphertext:
        file.write(f"{num}\n")  # 每个密文占一行

# 执行RSA解密
decrypted_text, decryption_time = decrypt(ciphertext, keys['n'], keys['d'])

# 输出结果
print("p:", keys['p'])
print("q:", keys['q'])
print("Public key written to 'public_key.txt'")
print("Private key written to 'private_key.txt'")
print("Ciphertext written to 'ciphertext.txt'")
print("Decrypted text:", decrypted_text)
print("Encryption time (seconds):", encryption_time)
print("Decryption time (seconds):", decryption_time)
