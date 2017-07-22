#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Imports
import re

class Validate(object):
    """
    Validation class for data integrity
    """

    @staticmethod
    def is_email(email_address):
        """
        Check if email is in proper format - test@test.com
        """
        if re.match("^[a-zA-Z0-9._%-]+@[a-zA-Z0-9._%-]+.[a-zA-Z]{2,6}$", \
                    email_address):
            return True
        else:
            return False

    @staticmethod
    def is_phone(phone_number):
        """
        Check if phone number is in proper format - 555-555-5555
        """
        if re.match("^(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?([0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(\d+))?$", \
                    phone_number):
            return True
        else:
            return False

    @staticmethod
    def is_ip(ip_address):
        """
        Check if IP address is in proper format 192.168.1.1
        """
        if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", \
                    ip_address):
            return True
        else:
            return False

    @staticmethod
    def is_regex_match(needle, haystack):
        """
        Run generic regular expressions for match
        """
        if re.search(needle, haystack, re.M|re.I):
            return True
        else:
            return False

    @staticmethod
    def is_length(text, length):
        """
        Verify text is exact length
        """
        if len(text) == length:
            return True
        else:
            return False

    @staticmethod
    def is_no_more_than_max_length(text, length):
        """
        Verify text is no bigger than max length
        """
        if len(text) <= length:
            return True
        else:
            return False

    @staticmethod
    def is_at_least_min_length(text, length):
        """
        Verify text is no less than min length
        """
        if len(text) >= length:
            return True
        else:
            return False

    @staticmethod
    def is_mac(mac):
        """
        Verify valid MAC address xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
        """
        if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", \
                    mac.lower()):
            return True
        else:
            return False

    @staticmethod
    def is_in_list(needle, haystack):
        """
        Check if value is in list
        """
        if needle in haystack:
            return True
        else:
            return False

    @staticmethod
    def is_in_dict_keys(needle, haystack):
        """
        Check if key exists in dict
        """
        if needle in haystack.keys():
            return True
        else:
            return False

    @staticmethod
    def is_in_dict_values(needle, haystack):
        """
        Check if value exists in dict
        """
        if needle in haystack.values():
            return True
        else:
            return False
