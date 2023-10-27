import os
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


def encrypt_file(input_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    encrypt_data = crypt_sm4.crypt_ecb(data)
    output_file = input_file + '.enc'
    with open(output_file, 'wb') as f:
        f.write(encrypt_data)


def decrypt_file(input_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_DECRYPT)
    decrypt_data = crypt_sm4.crypt_ecb(data)
    output_file = input_file.replace('.enc', '')
    with open(output_file, 'wb') as f:
        f.write(decrypt_data)


if __name__ == "__main__":
    key = os.urandom(16)
    encrypt_file('D:/D/Documents/Desktop/1.png', key)
    decrypt_file('D:/D/Documents/Desktop/1.png.enc', key)
