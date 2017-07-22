#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Imports
from Crypto import Random
from Crypto.Cipher import AES
import subprocess
import base64
import hashlib

# Custom Imports
from ga.lib.log import Log

class Encrypt(object):
    """
    Class to encrypt/decrypt data
    """

    @staticmethod
    def pad(current_string, current_length=32, pad_with="{"):
        """
        Pad AES key with chars to match length
        """
        while len(current_string) < current_length:
            current_string += str(pad_with)
        return current_string

    @staticmethod
    def encrypt(plaintext, shared_key):
        """
        Encrypt plaintext values with pre-shared key
        """
        encrypted_str = ""
        try:
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(Encrypt.pad(shared_key), AES.MODE_CFB, iv)
            encrypted_str = base64.b64encode(iv + cipher.encrypt(plaintext))
        except Exception, e_obj:
            Log.elog(str(e_obj))
        return encrypted_str

    @staticmethod
    def decrypt(ciphertext, shared_key):
        """
        Decrypt ciphertext values with pre-shared key
        """
        decrypted_str = ""
        try:
            ciphertext = base64.b64decode(ciphertext)
            iv = ciphertext[:AES.block_size]
            cipher = AES.new(Encrypt.pad(shared_key), AES.MODE_CFB, iv)
            decrypted_str = cipher.decrypt(ciphertext[AES.block_size:])
        except Exception, e_obj:
            Log.elog(str(e_obj))
        return decrypted_str

    @staticmethod
    def encrypt_multiple(plaintext, shared_keys):
        """
        Encrypt plaintext values with multiple pre-shared keys
        """
        encrypted_str = ""
        try:
            for shared_key in shared_keys:
                if shared_keys.index(shared_key) != 0:
                    plaintext = encrypted_str
                encrypted_str = Encrypt.encrypt(plaintext, shared_key)
        except Exception, e_obj:
            Log.elog(str(e_obj))
        return encrypted_str

    @staticmethod
    def decrypt_multiple(ciphertext, shared_keys):
        """
        Decrypt ciphertext values with multiple pre-shared keys
        """
        decrypted_str = ""
        shared_keys.reverse()
        try:
            for shared_key in shared_keys:
                if shared_keys.index(shared_key) != 0:
                    ciphertext = decrypted_str
                decrypted_str = Encrypt.decrypt(ciphertext, shared_key)
        except Exception, e_obj:
            Log.elog(str(e_obj))
        return decrypted_str

    @staticmethod
    def sha256(plaintext):
        """
        Hash text using sha256
        """
        hashed_str = ""
        try:
            hashed_str = hashlib.sha256(plaintext).hexdigest()
        except Exception, e_obj:
            Log.elog(str(e_obj))
        return hashed_str
