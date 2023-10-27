from gmssl import sm3, func

def sm3_hash(param):
    M = sm3.sm3_hash(func.bytes_to_list(param.encode("utf-8")))

    return M

if __name__ == '__main__':
    m = "This is the data to be hashed"

    M = sm3_hash(m)
    print(M)
