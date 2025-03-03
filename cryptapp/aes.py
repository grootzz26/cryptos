import hashlib
import base64
import logging
from Crypto import Random
from Crypto.Cipher import AES


LOGGER = logging.getLogger("myplex_service.apps.middlewares.security.aes")

IV = AES.block_size * '\x00'

BS = AES.block_size

pad = lambda s: s + bytes([BS - len(s) % BS] * (BS - len(s) % BS))
unpad = lambda s: s[:-ord(s[len(s)-1:])]


def encrypt(key, plain_text, iv=None):
    try:
        if not iv:
            iv = IV
        iv = iv.encode("utf-8")
        key = key.encode('utf-8')
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        encrypted_text = encryptor.encrypt(pad(plain_text))
        return base64.b64encode(encrypted_text).decode("utf-8")
    except Exception as e:
        LOGGER.error("Exception: while encrypt the data :%s",e)
        return None


def decrypt(key, plain_text, iv=None):
    try:
        if not iv:
            iv = IV
        iv = iv.encode("utf-8")
        key = key.encode("utf-8")
        plain_text = str(plain_text).replace('%2b','+').replace("%2B", "+").replace(" ", "+")
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        response = decryptor.decrypt(base64.b64decode(plain_text))
        return unpad(response)
    except Exception as e:
        LOGGER.error("Exception: while decrypt the data :%s",e)
        return None
