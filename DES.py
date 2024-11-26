from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def des_encrypt(message: str, key: bytes) -> bytes:
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes long.")
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 8))

def des_decrypt(ciphertext: bytes, key: bytes) -> str:
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes long.")
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 8).decode()

if __name__ == "__main__":
    message = "HELLODES"
    key = b"8bytekey"
    
    encrypted_message = des_encrypt(message, key)
    print(encrypted_message.hex())
    
    decrypted_message = des_decrypt(encrypted_message, key)
    print(decrypted_message)
