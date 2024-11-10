import random
import urandom
import os

def randbelow(n):
   # Generate a 256-bit random number by combining eight 32-bit parts
    privKey = 0
    for i in range(8):
        privKey = (privKey << 32) | random.getrandbits(32)

    # Ensure privKey is within the curve order by taking modulo
    privKey = privKey % n

    #print(privKey)
    return privKey

def randomBytes(n):
    random_bytes = bytearray(n)
    for i in range(n):
        random_bytes[i] = urandom.getrandbits(8)
    return bytes(random_bytes)

if __name__ == "__main__":
    p = os.urandom(16)
    print(p)
