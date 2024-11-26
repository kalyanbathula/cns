from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_encrypt(message: str, key: bytes) -> bytes:
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long.")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), AES.block_size))

def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long.")
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

if __name__ == "__main__":
    aes_key = b"thisis16bytekey"
    aes_message = "HELLOAES"

    encrypted_aes = aes_encrypt(aes_message, aes_key)
    print(encrypted_aes.hex())

    decrypted_aes = aes_decrypt(encrypted_aes, aes_key)
    print(decrypted_aes)
