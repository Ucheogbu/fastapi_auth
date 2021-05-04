import hashlib

def encrypt_password(password: str):
    return hashlib.sha224(password.encode('utf-8')).hexdigest()

def check_password(hashed_pass: str, password: str):
    return True if hashlib.sha224(password.encode('utf-8')).hexdigest() == hashed_pass else False
        