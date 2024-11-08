def mod_pow(b, exp, mod):
    res = 1
    b = b % mod  # b < mod

    while exp > 0:
        if (exp % 2) == 1:
            res = (res * b) % mod

        exp = exp // 2
        b = (b * b) % mod

    return res
