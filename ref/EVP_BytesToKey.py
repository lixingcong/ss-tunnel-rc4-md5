# https://github.com/dgkang/shadowsocks-python/blob/master/shadowsocks/encrypt.py

import hashlib

def EVP_BytesToKey(password, key_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    m = []
    i = 0
    while len(b''.join(m)) < key_len:
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    return ms

if __name__ == "__main__":
    pwd=b'hello'
    a = EVP_BytesToKey(pwd, 16)
    print(a.hex())
    print(len(a))
