import random
import time
import argparse

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

def generate_keys(pub_file_path, priv_file_path):
    p = gen_prime(64)
    q = gen_prime(64)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = gen_prime(64)
    d = mod_inv(e, phi_n)

    with open(pub_file_path, 'w') as pub_file:
        pub_file.write(f"n: {n}\n")
        pub_file.write(f"e: {e}\n")

    with open(priv_file_path, 'w') as priv_file:
        priv_file.write(f"d: {d}\n")

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
    return ciphertext, end_time - start_time

def decrypt(ciphertext, n, d):
    decrypted = ''
    start_time = time.time()
    
    for num in ciphertext:
        decrypted_pair = mod_pow(num, d, n)
        dechar_1 = chr(decrypted_pair // 1000)
        dechar_2 = chr(decrypted_pair % 1000)
        decrypted += dechar_1 + dechar_2

    end_time = time.time()
    return decrypted, end_time - start_time

def read_keys(pub_file_path, priv_file_path):
    with open(pub_file_path, 'r') as pub_file:
        pub_data = pub_file.readlines()
        n = int(pub_data[0].split(': ')[1])
        e = int(pub_data[1].split(': ')[1])
    
    with open(priv_file_path, 'r') as priv_file:
        d = int(priv_file.readline().split(': ')[1])

    return n, e, d

def main():
    parser = argparse.ArgumentParser(description='RSA Encryption and Decryption')
    parser.add_argument('mode', choices=['-e', '-d', '-g'], help='Mode: -e (encrypt), -d (decrypt), -g (generate keys)')
    parser.add_argument('input', help='Input file (plaintext for encryption, ciphertext for decryption, or filenames for keys generation)')
    parser.add_argument('output', help='Output file (public/private key filenames for key generation)')

    args = parser.parse_args()

    if args.mode == '-g':
        pub_file_path = args.input
        priv_file_path = args.output
        generate_keys(pub_file_path, priv_file_path)
        print(f"Public key written to '{pub_file_path}'")
        print(f"Private key written to '{priv_file_path}'")

    elif args.mode == '-e':
        plaintext_file = args.input
        pub_file_path = args.output
        
        with open(plaintext_file, 'r') as file:
            plaintext = file.read()
        
        n, e, _ = read_keys(pub_file_path, None)
        ciphertext, _ = encrypt(plaintext, n, e)

        with open('ciphertext.txt', 'w') as file:
            for num in ciphertext:
                file.write(f"{num}\n")  # 每个密文占一行

        print("Ciphertext written to 'ciphertext.txt'")

    elif args.mode == '-d':
        ciphertext_file = args.input
        priv_file_path = args.output
        
        with open(ciphertext_file, 'r') as file:
            ciphertext = [int(line.strip()) for line in file]
        
        _, _, d = read_keys(None, priv_file_path)
        n = None  # 可以在这里实现读取 n 的逻辑
        decrypted_text, _ = decrypt(ciphertext, n, d)

        print("Decrypted text:", decrypted_text)

if __name__ == '__main__':
    main()
