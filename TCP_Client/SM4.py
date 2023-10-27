from gmssl import sm4


def sm4_encode(key, data):
    """
    国密sm4加密
    :param key: 密钥
    :param data: 原始数据
    :return: 密文hex
    """
    for i in range(16 - len(key)):
        key = "0" + key

    sm4Alg = sm4.CryptSM4()  # 实例化sm4
    sm4Alg.set_key(key.encode(), sm4.SM4_ENCRYPT)  # 设置密钥
    dateStr = str(data)

    enRes = sm4Alg.crypt_ecb(dateStr.encode())  # 开始加密,bytes类型，ecb模式
    enHexStr = enRes.hex()

    return enHexStr  # 返回十六进制值
    # return encrypt_value.hex()


def sm4_decode(key, data):
    """
    国密sm4解密
    :param key: 密钥
    :param data: 密文数据
    :return: 明文hex
    """
    for i in range(16 - len(key)):
        key = "0" + key

    sm4Alg = sm4.CryptSM4()  # 实例化sm4
    sm4Alg.set_key(key.encode(), sm4.SM4_DECRYPT)  # 设置密钥
    deRes = sm4Alg.crypt_ecb(bytes.fromhex(data))  # 开始解密。十六进制类型,ecb模式
    deHexStr = deRes.decode()


    return deHexStr


if __name__ == '__main__':
    key = "123"
    strData = "12345abcde"
    for i in range(16 - len(key)):
        key = "0" + key

    enHexRes = sm4_encode(key, strData);

    print("解密测试===", enHexRes);

    sm4_decode(key, enHexRes);
