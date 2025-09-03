from cryptography.fernet import Fernet

# Generate key once, save securely, reuse same key
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

def encrypt_message(message: str) -> bytes:
    return cipher.encrypt(message.encode())

def decrypt_message(token: bytes) -> str:
    return cipher.decrypt(token).decode()
