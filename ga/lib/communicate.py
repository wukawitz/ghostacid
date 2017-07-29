#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Imports
import socket
import uuid

# Custom Imports
from ga.lib.log import Log

class Communicate(object):
    """
    Class for communicating with agents
    """

    def __init__(self, host, port):
        """
        Communicate constructor
        """
        self.id = self._generate_id()
        self.host = host
        self.port = port
        self.sock = socket.socket()

    def get_id(self):
        """
        Return instance id
        """
        return self.id

    def create_socket_and_listen(self, callback):
        """
        Create socket, listen and process data, provide a response
        """
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            while True:
                conn, addr = self.sock.accept()
                data = ""
                part = None
                while part != "":
                    part = conn.recv(1024)
                    data += part
                response = self._process_data(data, callback)
                conn.send(response)
                conn.close()
        except Exception, e_obj:
            Log.elog(str(e_obj))

    def close_socket():
        """
        Close the socket completely
        """
        try:
            self.sock.close()
        except Exception, e_obj:
            Log.elog(str(e_obj))

    def _process_data(self, data, callback):
        """
        Process data sent by the client
        """
        response = ""
        try:
            response = callback(data)
        except Exception, e_obj:
            Log.elog(str(e_obj))
        return response

    def _generate_id(self):
        """
        Static method for generating instance ids
        """
        return str(uuid.uuid4())
