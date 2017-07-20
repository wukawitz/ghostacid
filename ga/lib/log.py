#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Imports
import datetime

# Custom Imports
from ga.config.config import INFORMATION_LOG
from ga.config.config import ERROR_LOG

class Log(object):
    """
    Log all activity and events
    """

    @staticmethod
    def _clean(message):
        """
        Clean the message and return the time
        """
        current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = message.strip()
        return "{0}\t{1}\n".format(current_date, message)

    @staticmethod
    def _write(log_file, message):
        """
        Write the log message
        """
        with open(log_file, "a") as f_obj:
            f_obj.write(message)

    @staticmethod
    def ilog(message):
        """
        Log informational messages
        """
        try:
            log_message = Log._clean(message)
            Log._write(INFORMATION_LOG, log_message)
        except Exception, e_obj:
            pass

    @staticmethod
    def elog(message):
        """
        Log error messages
        """
        try:
            log_message = Log._clean(message)
            Log._write(ERROR_LOG, log_message)
        except Exception, e_obj:
            pass
