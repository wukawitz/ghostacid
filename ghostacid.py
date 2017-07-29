#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Custom Imports
from ga.lib.encrypt import Encrypt
from ga.lib.log import Log
from ga.lib.validate import Validate
from ga.lib.communicate import Communicate

def main():
    """
    Main entry into the application
    """
    pass

def test():
    """
    Function for testing - to be deleted
    """

    def test_func(text):
        return "You said: {0}".format(text)

    c_obj = Communicate("127.0.0.1", 8080)
    c_obj.create_socket_and_listen(test_func)

if __name__ == "__main__":

    main()
    test()
