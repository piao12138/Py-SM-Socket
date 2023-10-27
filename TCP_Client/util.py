from Crypto.Util import number


def string2int(s):
    # return int.from_bytes(s.encode("utf-8"), byteorder = "big")
    return number.bytes_to_long(s.encode("utf-8"))

def int2string(n):
    # return (n.to_bytes(((n.bit_length() + 7) //8), byteorder = "big")).decode("utf-8")
    return number.long_to_bytes(n)