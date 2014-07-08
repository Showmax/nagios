#!/usr/bin/python2.7
"""
Copyright (c) 2014, ICFLIX Media FZ LLC All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.

Desc: Take whatever is given on STDIN, "encrypt it", HTTP POST it to the server
"""
import argparse
import base64
import hashlib
import logging
import logging.handlers
import os
import pyinotify
import Queue
import requests
import signal
from socket import getfqdn
import subprocess
import sys
import threading
import traceback

# Interval of sending results in sec
DEFAULT_INTERVAL = 60
DEFAULT_ENVIRONMENT = 'development'
# Path to check_multi script
CHECK_MULTI_BIN = '/usr/lib/nagios/plugins/check_multi'
# Directory with check_multi commands; no trailing '/'!
CHECK_MULTI_DIR = '/etc/check_multi'
# Log format
LOG_FORMAT = '%(asctime)s %(levelname)-10s %(threadName)-11s %(message)s'

# check_multi commands to execute in order to send config/results
CMD_GET_CONFIG = [CHECK_MULTI_BIN,
        '-f',
        CHECK_MULTI_DIR,
        '-s',
        'HOSTNAME="%s"' % (getfqdn()),
        '-r',
        '2048' ]
CMD_GET_RESULTS = [CHECK_MULTI_BIN,
        '-f',
        CHECK_MULTI_DIR,
        '-r',
        '256' ]

# MyPie {{{
class MyPie(pyinotify.ProcessEvent):
    """ Class to Process Inotify Events """

    def __init__(self, mqueue):
        pyinotify.ProcessEvent.__init__(self)
        self.mqueue = mqueue

    def _enqueue(self, event_desc, filename):
        """ Enqueue events for MainThread """
        try:
            self.mqueue.put((event_desc, filename))
        except Queue.Full:
            # We're not going to signal back any failures
            pass

    def process_IN_DELETE(self, event):
        """ Deleted """
        self._enqueue('deleted', os.path.join(event.path, event.name))

    def process_IN_CREATE(self, event):
        """ Created """
        self._enqueue('created', os.path.join(event.path, event.name))

    def process_IN_MODIFY(self, event):
        """ Modified """
        self._enqueue('modified', os.path.join(event.path, event.name))

    def process_IN_ATTRIB(self, event):
        """ Attribute change """
        self._enqueue('attr_change', os.path.join(event.path, event.name))

    def process_IN_MOVED_FROM(self, event):
        """ Moved from somewhere """
        self._enqueue('moved_from', os.path.join(event.path, event.name))

    def process_IN_CLOSE_WRITE(self, event):
        """ Written to """
        self._enqueue('written', os.path.join(event.path, event.name))

    def process_IN_MOVED_TO(self, event):
        """ Moved to """
        self._enqueue('moved_to', os.path.join(event.path, event.name))


# }}}
# NagiosRunit {{{
class NagiosRunit(object):
    """ Nagios Client/Node executed from runit """

    def __init__(self):
        self.environment = DEFAULT_ENVIRONMENT
        self.inotifier = None
        self.interval = DEFAULT_INTERVAL
        self.mqueue = Queue.Queue(0)
        self._stop = threading.Event()

    def _stop_inotifier(self):
        """ Stop inotify thread """
        try:
            self.inotifier.stop()
            self.inotifier.join(5)
        except Exception:
            pass

    def handler_signal(self, _):
        """ Handle signals, resp. set event """ 
        self._stop.set()

    def run(self):
        """ Main """
        signal.signal(signal.SIGHUP, self.handler_signal)
        signal.signal(signal.SIGINT, self.handler_signal)
        signal.signal(signal.SIGTERM, self.handler_signal)
        vm = pyinotify.WatchManager()
        mask = pyinotify.ALL_EVENTS
        self.inotifier = pyinotify.ThreadedNotifier(vm, MyPie(self.mqueue))
        self.inotifier.start()
        vm.add_watch(CHECK_MULTI_DIR, mask, rec=False)
        while self._stop.isSet() is False:
            self.send_results()
            self.send_config()
            self._stop.wait(self.interval)

        self.stop()

    def send_results(self):
        """ Send results to remote Nagios Host """
        sender = NagiosSender()
        sender.set_command(CMD_GET_RESULTS)
        sender.set_url('%s%s' % (NAGIOS_HOST, RESULTS_URI))
        sender.set_shared_key(SHARED_KEY)
        try:
            sender.run()
        except Exception:
            logging.error(traceback.format_exc())
            self._stop.set()

        del sender

    def send_config(self):
        """ Send updates done to CHECK_MULTI_DIR to remote Host """
        if self.mqueue.qsize() < 1:
            return

        while True:
            try:
                (event_desc, fpath) = self.mqueue.get()
                logging.info("Event %s on file %s", event_desc, fpath)
            except Queue.Empty:
                break

        sender = NagiosSender()
        sender.set_command(CMD_GET_CONFIG)
        sender.set_shared_key(SHARED_KEY)
        sender.set_url('%s%s' % (NAGIOS_HOST, CONFIG_URI))
        try:
            sender.run()
        except Exception:
            logging.error(traceback.format_exc())
            self._stop.set()

        del sender

    def set_environment(self, environment):
        """ Set working environment """
        self.environment = environment

    def set_interval(self, interval):
        """ Set interval for sending results """
        self.interval = interval

    def stop(self):
        """ Stop everything """
        self._stop.set()
        self._stop_inotifier()


# }}}
# NagiosSender {{{
class NagiosSender(object):
    """ Nagios Client/Node class - accept STDIN, encrypt and HTTP POST it """

    def __init__(self):
        self.command = None
        self.url = None
        self.shared_key = None
        self.http_timeout = 15

    def encode(self, key, string):
        """ Encrypt given string with given key """
        encoded_chars = []
        for i in xrange(len(string)):
            key_c = key[i % len(key)]
            encoded_c = chr(ord(string[i]) + ord(key_c) % 256)
            encoded_chars.append(encoded_c)

        encoded_string = "".join(encoded_chars)
        return base64.urlsafe_b64encode(encoded_string)

    def decode(self, key, string):
        """ Try to decrypt given string with given key """
        decoded_chars = []
        string = base64.urlsafe_b64decode(string)
        for i in xrange(len(string)):
            key_c = key[i % len(key)]
            encoded_c = chr(abs(ord(string[i]) - ord(key_c) % 256))
            decoded_chars.append(encoded_c)

        decoded_string = ''.join(decoded_chars)
        return decoded_string

    def run(self):
        """ Go, go, go! """
        logging.debug('Command %s', " ".join(self.command))
        stdin = self.run_command(self.command)
        if stdin is None:
            # This is to keep cron quiet
            # TODO - however, don't forget to send metrics!
            sys.exit(0)

        checksum = hashlib.sha256(stdin).hexdigest()
        data = 'CHECKSUM: %s\n' % (checksum)
        data += 'FQDN: %s\n' % (getfqdn())
        data += '---\n'
        data += stdin
        encoded = self.encode(self.shared_key, data)
        headers = {'content-type': 'text/plain'}
        rsp = requests.post(self.url, data=encoded, headers=headers,
                timeout=self.http_timeout)

        try:
            status_code = int(rsp.status_code)
        except Exception:
            status_code = 0

        logging.debug('Status code is %i', status_code)
        # TODO - What are we going to do on error?
        if status_code != 200:
            # FAIL
            pass

        #print rsp.raw.read()

    def run_command(self, cmd):
        """ Run given command and return its STDOUT """
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        except Exception as exception:
            logging.error('Failed to execute command: %s', exception)
            return None

        (stdout_lines, stderr_lines) = proc.communicate()
        if stderr_lines is not None:
            logging.error('Command has returned some errors.')
            return None

        if stdout_lines is None or len(stdout_lines) < 1:
            logging.error('Command has returned no lines.')
            return None

        return stdout_lines

    def set_command(self, command):
        """ Set command to execute - list is expected """
        self.command = command

    def set_shared_key(self, shared_key):
        """ Set shared key for scrambling message """
        self.shared_key = shared_key

    def set_url(self, url):
        """ Set URL we're going to POST to """
        self.url = url


# }}}
def get_actions():
    """ Return list of available actions """
    return ['runit', 'send_config', 'send_results']

def get_environments():
    """ Return list of supported environments """
    return ['production', 'staging', 'development']

def main():
    """ main function - setup logging and launch instance of NagiosSender """
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', dest='action', type=str, help='action to do',
            choices=get_actions())
    parser.add_argument('-e', dest='environment', type=str, help='environment',
            choices=get_environments(), default=DEFAULT_ENVIRONMENT)
    parser.add_argument('-i', dest='interval', type=int,
            help='how often to send check results', default=DEFAULT_INTERVAL)
    parser.add_argument('-v', dest='verbose', action='store_true',
            help='add to logging verbosity')
    args = parser.parse_args()
    # Set up logging.
    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG

    logging.basicConfig(format=LOG_FORMAT, stream=sys.stdout)
    logging.getLogger().setLevel(log_level)

    # Yes, we want to crash loud if some of those aren't provided
    SHARED_KEY = os.environ['NAGIOS_SHARED_KEY']
    NAGIOS_HOST = os.environ['NAGIOS_HOST']
    CONFIG_URI = os.environ['NAGIOS_CONFIG_URI']
    RESULTS_URI = os.environ['NAGIOS_RESULTS_URI']

    if args.action == 'send_config':
        nagios_sender = NagiosSender()
        nagios_sender.set_command(CMD_GET_CONFIG)
        nagios_sender.set_shared_key(SHARED_KEY)
        nagios_sender.set_url('%s%s' % (NAGIOS_HOST, CONFIG_URI))
        nagios_sender.run()
    elif args.action == 'send_results':
        nagios_sender = NagiosSender()
        nagios_sender.set_command(CMD_GET_RESULTS)
        nagios_sender.set_url('%s%s' % (NAGIOS_HOST, RESULTS_URI))
        nagios_sender.set_shared_key(SHARED_KEY)
        nagios_sender.run()
    elif args.action == 'runit':
        nagios_runit = NagiosRunit()
        nagios_runit.set_interval(args.interval)
        nagios_runit.set_environment(args.environment)
        nagios_runit.run()

    logging.shutdown()

if __name__ == '__main__':
    main()
