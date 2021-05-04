from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import secrets
from datetime import datetime, timedelta


def _encode_aes(cipher, password, block_size):
    # print(type(password))
    return base64.b64encode(cipher.encrypt(pad(password, block_size)))

def _decode_aes(cipher, _encoded, block_size):
    return unpad(cipher.decrypt(base64.b64decode(_encoded)), block_size)

def gen_ciph(block_size=32):
    s = secrets.token_hex(block_size)
    ciph = AES.new(s.encode('utf-8'), AES.MODE_ECB)
    return [s, ciph]

def get_cipher(key: str):
    return AES.new(key, AES.MODE_ECB)
    
def _encode_data(data, cipher, block_size=32):
    
    encoded_data = _encode_aes(cipher, data, block_size)

    return _encode_aes(cipher, encoded_data, block_size)

def _decode_data(data, cipher, block_size=32):
    decoded_data = _decode_aes(cipher, data, block_size)
    return _decode_aes(cipher, decoded_data, block_size)

def get_token(username):
    timestamp = datetime.now().timestamp()
    key, cipher = gen_ciph(block_size=8)
    encoded_username = _encode_data(username.encode('utf-8'), cipher, block_size=16)
    encoded_timestamp = _encode_data(str(timestamp).encode('utf-8'), cipher, block_size=16)

    byte_token = encoded_timestamp + encoded_username + key.encode('utf-8')

    return byte_token.decode('utf-8')

def decode_token(token):
    token = token.encode('utf-8')
    encoded_timestamp = token[:64]
    encoded_username = token[64:-16]
    key = token[-16:]
    cipher = get_cipher(key)

    now = datetime.now()
    raw_timestamp = _decode_data(encoded_timestamp, cipher, block_size=16).decode('utf-8')
    timestamp = datetime.fromtimestamp(float(raw_timestamp))
    if ((now - timestamp).seconds / 60) > 30:
        raise RuntimeError('Token Has Expired')
    else:
        return _decode_data(encoded_username, cipher, block_size=16).decode('utf-8')
