from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad

def blowfish_encrypt(message: str, key: bytes) -> bytes:
    if not (4 <= len(key) <= 56):
        raise ValueError("Key must be between 4 and 56 bytes long.")
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), Blowfish.block_size))

def blowfish_decrypt(ciphertext: bytes, key: bytes) -> str:
    if not (4 <= len(key) <= 56):
        raise ValueError("Key must be between 4 and 56 bytes long.")
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), Blowfish.block_size).decode()

if __name__ == "__main__":
    key = b"blowfishkey"
    message = "HELLOBLOWFISH"

    encrypted_message = blowfish_encrypt(message, key)
    print(encrypted_message.hex())

    decrypted_message = blowfish_decrypt(encrypted_message, key)
    print(decrypted_message)
