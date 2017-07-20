#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Imports
from Crypto import Random
from Crypto.Cipher import AES
import subprocess
import base64

class Encrypt(object):
    """
    Encrypt class for securing data
    """

    @staticmethod
    def encrypt_data(encrypt_key, data):
        """
        Encrypt data using AES
        """
        encrypted_str = ""
        try:
            new_data = data + (AES.block_size - len(data) % AES.block_size) * \
                              chr(AES.block_size - len(data) % AES.block_size)
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(encrypt_key, AES.MODE_CBC, iv)
            encrypted_str = base64.b64encode(iv + cipher.encrypt(new_data))
        except Exception, e_obj:
            print "[!] ERROR: {0}".format(str(e_obj))
        return encrypted_str

    @staticmethod
    def decrypt_data(encrypt_key, encoded_data):
        """
        Decrypt data using AES
        """
        decrypted_str = ""
        try:
            new_data = base64.b64decode(encoded_data)
            iv = new_data[:AES.block_size]
            cipher = AES.new(encrypt_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(new_data[AES.block_size:])
            decrypted_str = decrypted[0:-ord(decrypted[-1])]
        except Exception, e_obj:
            print "[!] ERROR: {0}".format(str(e_obj))
        return decrypted_str
