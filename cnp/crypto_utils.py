# Capacity cryptography utilities

from web3 import Web3
import sys
import base64
import ecies.utils
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def get_new_keypair():
    ekey = ecies.utils.generate_eth_key()
    return (ekey.to_hex(), ekey.public_key.to_hex())


# Decrypt an ECIES message. Ideally, all we'd need is:
# ecies.decrypt(Web3.toHex(hexstr=crypto_keys["private"]), Web3.toBytes(base64.b64decode(enc_msg))).decode("utf-8")
# but the eciespy library uses a packed format, a different AES mode and different mac size than eccrypto.js
# so let's roll our own function here.
# Also, ecies uses libsecp256k1 which has an ECDH implementation incompatible with other libs, see below.
# Still modeled after https://github.com/kigawas/eciespy
def ecies_decrypt(privkey, message_parts, logger=None):
    # WARNING: ECDH gives different results depending on using libsecp256k1 or a different libary for secp256k1.
    # See https://github.com/ofek/coincurve/issues/9 and
    # https://crypto.stackexchange.com/questions/57695/varying-ecdh-key-output-on-different-ecc-implementations-on-the-secp256k1-curve
    # eciespy uses coincurve which builds on libsecp256k1, while e.g. eccrypto.js uses a different, standard crypto lib.
    # Code below would do the eciespy ECDH:
    # private_key = ecies.utils.hex2prv(Web3.toHex(hexstr=privkey))
    # sender_public_key = ecies.utils.hex2pub(Web3.toHex(message_parts["ephemPublicKey"]))
    # aes_shared_key = ecies.utils.derive(private_key, sender_public_key) # <-- this gives the libsecp256k1 version, which we can't use!
    # Functions below use the cryptography module to get the non-libsecp256k1 version.
    sender_public_key_obj = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256K1(), message_parts["ephemPublicKey"]).public_key(default_backend())
    private_key_obj = ec.derive_private_key(Web3.toInt(hexstr=privkey), ec.SECP256K1(), default_backend())
    aes_shared_key = private_key_obj.exchange(ec.ECDH(), sender_public_key_obj)
    # Now let's do AES-CBC with this, including the hmac matching (modeled after eccrypto code).
    aes_keyhash = hashlib.sha512(aes_shared_key).digest()
    hmac_key = aes_keyhash[32:]
    test_hmac = hmac.new(hmac_key, message_parts["iv"] + message_parts["ephemPublicKey"] + message_parts["ciphertext"], hashlib.sha256).digest()
    if test_hmac != message_parts["mac"]:
        if logger:
            logger.error("Mac doesn't match: %s vs. %s", test_hmac.hex(), message_parts["mac"].hex())
        return False
    aes_key = aes_keyhash[:32]
    # Actual decrypt is modeled after ecies.utils.aes_decrypt() - but with CBC mode to match eccrypto.
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=message_parts["iv"])
    try:
        decrypted_bytes = aes_cipher.decrypt(message_parts["ciphertext"])
        # Padding characters (unprintable) may be at the end to fit AES block size, so strip them.
        unprintable_chars = bytes(''.join(map(chr, range(0, 32))).join(map(chr, range(127, 160))), 'utf-8')
        decrypted_string = decrypted_bytes.rstrip(unprintable_chars).decode("utf-8")
        return decrypted_string
    except:
        if logger:
            logger.error("Could not decode ciphertext: %s", sys.exc_info()[0])
        return False


# Encrypt an ECIES message (opposite of `ecies_decrypt`)
def ecies_encrypt(pubkey, raw_string):
    message_parts = {}
    ekey = ecies.utils.generate_eth_key()
    ephem_privkey = ekey.to_hex()
    message_parts["ephemPublicKey"] = ekey.public_key.to_hex()
    sender_public_key_obj = ec.EllipticCurvePublicNumbers.from_encoded_point(ec.SECP256K1(), pubkey).public_key(default_backend())
    private_key_obj = ec.derive_private_key(Web3.toInt(hexstr=ephem_privkey), ec.SECP256K1(), default_backend())
    aes_shared_key = private_key_obj.exchange(ec.ECDH(), sender_public_key_obj)
    # Now let's do AES-CBC with this, including create the hmac (modeled after eccrypto code).
    aes_keyhash = hashlib.sha512(aes_shared_key).digest()
    aes_key = aes_keyhash[:32]
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = aes_cipher.encrypt(pad(raw_string, AES.block_size))
    message_parts["iv"] = base64.b64encode(aes_cipher.iv).decode('utf-8')
    message_parts["ciphertext"] = base64.b64encode(ct_bytes).decode('utf-8')
    hmac_key = aes_keyhash[32:]
    message_parts["mac"] = hmac.new(hmac_key, message_parts["iv"] + message_parts["ephemPublicKey"] + message_parts["ciphertext"], hashlib.sha256).digest()
    return message_parts
