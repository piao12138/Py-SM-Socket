import pysmx
from gmssl import sm2, func
from pysmx.SM2 import generate_keypair
from base64 import b64encode, b64decode

# sm2的公私钥
SM2_PRIVATE_KEY = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
SM2_PUBLIC_KEY = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

sm2_crypt = sm2.CryptSM2(public_key=SM2_PUBLIC_KEY, private_key=SM2_PRIVATE_KEY)


# 加密
def encrypt(info):
    encode_info = sm2_crypt.encrypt(info.encode(encoding="utf-8"))
    encode_info = b64encode(encode_info).decode()  # 将二进制bytes通过base64编码
    return encode_info


# 解密
def decrypt(info):
    decode_info = b64decode(info.encode())  # 通过base64解码成二进制bytes
    decode_info = sm2_crypt.decrypt(decode_info).decode(encoding="utf-8")
    return decode_info


def signature(info, random_hex_str):
    signature = sm2_crypt.sign(info.encode("utf-8"), random_hex_str)

    return signature


def Verify(signature, info):
    verify = sm2_crypt.verify(signature, info.encode("utf-8"))

    return verify


def Encrypto(m, PUBLIC_KEY):
    cipher = pysmx.SM2.Encrypt(m, PUBLIC_KEY, 64)

    return cipher


def Decrypto(cipher, PRIVATE_KEY):
    plaint = pysmx.SM2.Decrypt(cipher, PRIVATE_KEY, 64)

    return str(plaint)[2:-1]


def Sign(m, PRIVATE_KEY, K):
    sign = pysmx.SM2.Sign(m, PRIVATE_KEY, K, 64)

    return sign


def Ver(sign, m, PUBLIC_KEY):
    ver = pysmx.SM2.Verify(sign, m, PUBLIC_KEY)

    return ver


if __name__ == "__main__":
    origin_pwd = '123456'
    random_hex_str = func.random_hex(sm2_crypt.para_len)

    print("gmssl-SM2\n")

    encrypy_pwd = encrypt(origin_pwd)
    print("Encrypto: ", encrypy_pwd)

    decrypt_pwd = decrypt(encrypy_pwd)
    print("Decrypto: ", decrypt_pwd)

    signature = signature(origin_pwd, random_hex_str)
    print("Signature: ", signature)

    verify = Verify(signature, origin_pwd)
    print("Verify: ", verify)

    print("\n\n\npysmx-SM2\n")

    len_para = 64
    PUBLIC_KEY, PRIVATE_KEY = generate_keypair(len_para)

    m = "1234567890"

    cipher = Encrypto(m, PUBLIC_KEY)
    print("cipher: ", cipher, "\n")

    plaint = Decrypto(cipher, PRIVATE_KEY)
    print("plaint: ", plaint, "\n")

    sign = Sign(m, PRIVATE_KEY, random_hex_str)
    print("sign: ", sign, "\n")

    plaint = Ver((sign.decode("latin-1")).encode("latin-1"), m, PUBLIC_KEY)
    print("ver: ", plaint, "\n")

