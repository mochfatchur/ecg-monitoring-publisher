import ec
import registry as reg
import randomize as random

# c = reg.get_curve("secp192r1")
# s = ec.Point(c, 0xd458e7d127ae671b0c330266d246769353a012073e97acf8, 0x325930500d851f336bddc050cf7fb11b5673a1645086df3b)
# t = ec.Point(c, 0xf22c4395213e9ebe67ddecdd87fdbd01be16fb059b9753a4, 0x264424096af2b3597796db48f8dfb41fa9cecc97691a9c79)
# r = s + t
# print(r)

curve = reg.get_curve('secp256k1')

def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def ecc_calc_encryption_keys(pubKey):
    ciphertextPrivKey = random.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    return (sharedECCKey, ciphertextPubKey)

def ecc_calc_decryption_key(privKey, ciphertextPubKey):
    sharedECCKey = ciphertextPubKey * privKey
    return sharedECCKey

if __name__ == "__main__":
    privKey = random.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    print("private key:", hex(privKey))
    print("public key:", compress_point(pubKey))

    (encryptKey, ciphertextPubKey) = ecc_calc_encryption_keys(pubKey)
    print("ciphertext pubKey:", compress_point(ciphertextPubKey))
    print("encryption key:", compress_point(encryptKey))

    decryptKey = ecc_calc_decryption_key(privKey, ciphertextPubKey)
    print("decryption key:", compress_point(decryptKey))
