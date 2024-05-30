from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, Blowfish
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA
import os

def caesar_encrypt(text, key):
    shift = int(key) % 26
    encrypted_text = ''.join([chr((ord(char) + shift - 65) % 26 + 65) if char.isupper() else chr((ord(char) + shift - 97) % 26 + 97) if char.islower() else char for char in text])
    return encrypted_text

def caesar_decrypt(text, key):
    shift = int(key) % 26
    decrypted_text = ''.join([chr((ord(char) - shift - 65) % 26 + 65) if char.isupper() else chr((ord(char) - shift - 97) % 26 + 97) if char.islower() else char for char in text])
    return decrypted_text

def vigenere_encrypt(text, key):
    key = key.upper()
    encrypted_text = ''
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            encrypted_text += chr((ord(char) + ord(key[i % len(key)]) - 2 * 65) % 26 + 65)
        elif char.islower():
            encrypted_text += chr((ord(char) + ord(key[i % len(key)]) - 65 - 97) % 26 + 97)
        else:
            encrypted_text += char
    return encrypted_text

def vigenere_decrypt(text, key):
    key = key.upper()
    decrypted_text = ''
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            decrypted_text += chr((ord(char) - ord(key[i % len(key)]) + 26) % 26 + 65)
        elif char.islower():
            decrypted_text += chr((ord(char) - ord(key[i % len(key)]) + 26) % 26 + 97)
        else:
            decrypted_text += char
    return decrypted_text

def aes_encrypt(text, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    key = key.ljust(32)[:32].encode()
    iv = b'0' * 16

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(encrypted_data).decode()

def aes_decrypt(text, key):
    encrypted_data = base64.b64decode(text)

    key = key.ljust(32)[:32].encode()
    iv = b'0' * 16

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data.decode()

def rsa_encrypt(text, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_text = cipher.encrypt(text.encode())
    return b64encode(encrypted_text).decode()

def rsa_decrypt(text, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_text = cipher.decrypt(b64decode(text))
    return decrypted_text.decode()

def blowfish_encrypt(text, key):
    key = key.encode().ljust(56)[:56] 
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv
    padded_text = pad(text.encode(), Blowfish.block_size)
    encrypted_text = iv + cipher.encrypt(padded_text)
    return b64encode(encrypted_text).decode()

def blowfish_decrypt(text, key):
    key = key.encode().ljust(56)[:56]
    encrypted_text = b64decode(text)
    iv = encrypted_text[:Blowfish.block_size]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_text[Blowfish.block_size:]), Blowfish.block_size)
    return decrypted_text.decode()

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key

def encrypt(text, key, cipher):
    if cipher == 'caesar':
        return caesar_encrypt(text, key)
    elif cipher == 'vigenere':
        return vigenere_encrypt(text, key)
    elif cipher == 'aes':
        return aes_encrypt(text, key)
    elif cipher == 'rsa':
        return rsa_encrypt(text, key)
    elif cipher == 'blowfish':
        return blowfish_encrypt(text, key)

def decrypt(text, key, cipher):
    if cipher == 'caesar':
        return caesar_decrypt(text, key)
    elif cipher == 'vigenere':
        return vigenere_decrypt(text, key)
    elif cipher == 'aes':
        return aes_decrypt(text, key)
    elif cipher == 'rsa':
        return rsa_decrypt(text, key)
    elif cipher == 'blowfish':
        return blowfish_decrypt(text, key)