#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Standard Imports
from multiprocessing import Process

# Custom Imports
from ga.lib.log import Log

class Multiprocess(object):
    """
    Class for creating and handling multiple processes at once
    """

    def __init__(self):
        """
        Multiprocess constructor
        """
        self.processes = []

    def add_process(self, callback, data={}):
        """
        Add a process to the queue
        """
        try:
            p_obj = Process(target=callback, kwargs=data)
            self.processes.append(p_obj)
        except Exception, e_obj:
            Log.elog(str(e_obj))

    def start_processes(self):
        """
        Start all processes
        """
        try:
            if len(self.processes) > 0:
                for p_obj in self.processes:
                    p_obj.start()
        except Exception, e_obj:
            Log.elog(str(e_obj))

    def add_process_and_start(self, callback, data={}):
        """
        Add a process to the queue and start it
        """
        try:
            p_obj = Process(target=callback, kwargs=data)
            self.processes.append(p_obj)
            last_obj = self.processes[-1]
            last_obj.start()
        except Exception, e_obj:
            Log.elog(str(e_obj))
