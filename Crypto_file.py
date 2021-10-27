import re

from Cryptodome.Hash import MD2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


class CryptoTask:
    nonce = b'\x1e\x96\x99\xe0q\xbdjl\xcd\x08HV\xd4\xeb\x0f\xf8'
    key = b'f03881a88c6e39135f0ecc60efd609b9'
    encryptor = None

    def __init__(self, password):
        self.password ='password'
        f = open('key.txt', 'r')
        self.key = f.readline(0)
        self.nonce =f.readline(1)
        f.close()

    def make_crypt(self):
        print(self.key, self.nonce)
        self.key = b'f03881a88c6e39135f0ecc60efd609b9'
        self.nonce = b'\x1e\x96\x99\xe0q\xbdjl\xcd\x08HV\xd4\xeb\x0f\xf8'
        algorithm = algorithms.ChaCha20(self.key, self.nonce)
        cipher = Cipher(algorithm, mode=None)
        self.encryptor = cipher.encryptor()
        l = open('file.txt', 'r')
        text = l.read()
        l.close()
        text = text.encode('utf-8')
        crte = self.encryptor.update(text)
        l = open('file_encrypted.txt', 'wb')
        l.write(crte)
        l.close()
        #os.remove('file.txt')

    def make_decrypt(self, password):
        nonce = b'\x1e\x96\x99\xe0q\xbdjl\xcd\x08HV\xd4\xeb\x0f\xf8'
        key = b'f03881a88c6e39135f0ecc60efd609b9'
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()
        text = password
        text = input_to_pass(text)
        hash=myhash(text)
        print(str(hash))
        l = open('file_encrypted.txt', 'rb')
        ct = l.read()
        l.close()
        print(ct)
        dec = decryptor.update(ct)
        t = dec.decode('utf-8')
        print(t)
        l = open('file.txt', 'w')
        l.write(t)
        l.close()
        #os.remove('file_encrypted.txt')

def myhash(text):
    h = MD2.new()
    h.update(text)
    print(h.hexdigest())
    return h.hexdigest()

def input_to_pass(text):
    text =text.encode('utf-8')
    return text

def pass_to_bin(text):
    text = text.encode('utf-8')
    return text

c = CryptoTask('password')
#c.make_crypt()
c.make_decrypt('password')


