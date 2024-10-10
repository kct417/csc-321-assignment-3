from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from random import randint


def encrypt(key: bytes, plaintext: str, iv: bytes, block_size: int) -> bytes:
    """
    Encrypt the plaintext using the key and the IV

    :param key: The key used to encrypt the plaintext
    :param plaintext: The plaintext to encrypt
    :param iv: The initialization vector used to encrypt the plaintext
    :param block_size: The block size used to pad the plaintext
    """
    encoded_text = plaintext.encode()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(encoded_text, block_size))


def decrypt(key: bytes, ciphertext: bytes, iv: bytes, block_size: int) -> str:
    """
    Decrypt the ciphertext using the key and the IV

    :param key: The key used to encrypt the plaintext
    :param ciphertext: The ciphertext to decrypt
    :param iv: The initialization vector used to encrypt the plaintext
    :param block_size: The block size used to pad the plaintext
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encoded_text = unpad(cipher.decrypt(ciphertext), block_size)
    return encoded_text.decode()


def diffie_hellman_key_exchange_mitm(
    q: int, alpha: int, sender_private_key: int, reciever_private_key: int
) -> bytes:
    """
    Perform the Diffie-Hellman key exchange algorithm

    :param q: A large prime number
    :param alpha: A primitive root modulo q
    :param sender_private_key: The private key of the first party
    :param reciever_private_key: The private key of the second party
    """
    public_key = q  # public key intercepted by adversary
    # intercepted key forwarded to reciever as public key
    secret_key = pow(public_key, reciever_private_key, q)
    key_length = (secret_key.bit_length() + 7) // 8
    return SHA256.new(secret_key.to_bytes(key_length)).digest()[:16]


def main() -> None:
    # Suggested values for q and alpha
    q = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371"
    alpha = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 855E6EEB 22B3B2E5"

    # Convert the hexadecimal strings to integers
    q = int(q.replace(" ", ""), 16)
    alpha = int(alpha.replace(" ", ""), 16)

    # Alice and Bob generate their private keys
    x_a = randint(1, q - 1)
    x_b = randint(1, q - 1)
    x_c = q  # private key of the adversary

    # Alice and Bob generate their shared secret key
    key1 = diffie_hellman_key_exchange_mitm(q, alpha, x_a, x_c)
    key2 = diffie_hellman_key_exchange_mitm(q, alpha, x_b, x_c)
    key3 = diffie_hellman_key_exchange_mitm(q, alpha, x_b, x_c)
    print(f"Alice's symmetric key: {key1}")
    print(f"Bob's symmetric key: {key2}")
    print(f"Mallory's symmetric key: {key3}")

    # Alice and Bob encrypt their messages
    iv = get_random_bytes(16)
    message1 = f"Hi Bob!"
    message2 = f"Hi Alice!"
    ciphertext1 = encrypt(key1, message1, iv, AES.block_size)
    ciphertext2 = encrypt(key2, message2, iv, AES.block_size)

    # Alice and Bob decrypt the each other's ciphertexts
    plaintext1 = decrypt(key1, ciphertext2, iv, AES.block_size)
    plaintext2 = decrypt(key2, ciphertext1, iv, AES.block_size)
    plaintext3 = decrypt(key3, ciphertext1, iv, AES.block_size)

    print(f"Alice received: {plaintext1}")
    print(f"Bob received: {plaintext2}")
    print(f"Mallory received: {plaintext3}")


if __name__ == "__main__":
    main()
