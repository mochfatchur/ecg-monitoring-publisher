import os
import hashlib

# Define the elliptic curve parameters for NIST P-256
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162cbcec531f3cfa2fd45d7e19b2168d58
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


class ECDH:
    def __init__(self):
        # Private key (randomly generated)
        self.private_key = int.from_bytes(os.urandom(32), 'big') % n
        # Public key (G * private_key)
        self.public_key = self.point_multiply(Gx, Gy, self.private_key)

    def point_add(self, x1, y1, x2, y2):
        if x1 == x2 and y1 == y2:
            return self.point_double(x1, y1)

        m = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p
        x3 = (m * m - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return x3, y3

    def point_double(self, x, y):
        m = ((3 * x * x + a) * pow(2 * y, p - 2, p)) % p
        x3 = (m * m - 2 * x) % p
        y3 = (m * (x - x3) - y) % p
        return x3, y3

    def point_multiply(self, x, y, k):
        k = bin(k)[2:]
        Qx, Qy = x, y

        for i in range(1, len(k)):
            Qx, Qy = self.point_double(Qx, Qy)
            if k[i] == '1':
                Qx, Qy = self.point_add(Qx, Qy, x, y)

        return Qx, Qy

    def generate_shared_secret(self, other_public_key):
        # other_public_key is a tuple (x, y)
        shared_x, shared_y = self.point_multiply(other_public_key[0], other_public_key[1], self.private_key)
        # Derive a symmetric key using a hash function (e.g., SHA-256)
        shared_secret = hashlib.sha256(int.to_bytes(shared_x, 32, 'big')).digest()
        return shared_secret


# Example usage:

# Alice generates her key pair
alice = ECDH()
print("Alice's Public Key:", alice.public_key)

# Bob generates his key pair
bob = ECDH()
print("Bob's Public Key:", bob.public_key)

# Alice and Bob exchange public keys and generate a shared secret
alice_shared_secret = alice.generate_shared_secret(bob.public_key)
bob_shared_secret = bob.generate_shared_secret(alice.public_key)

print("Alice's Shared Secret:", alice_shared_secret)
print("Bob's Shared Secret:", bob_shared_secret)

# Verify that both shared secrets are identical
assert alice_shared_secret == bob_shared_secret
print("Shared secret matches!")

