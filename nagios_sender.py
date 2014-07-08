#!/usr/bin/python2.7
"""
Copyright (c) 2014, ICFLIX Media FZ LLC All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.

Desc: Take whatever is given on STDIN, "encrypt it", HTTP POST it to the server
"""
import base64
import hashlib
import logging
import logging.handlers
import requests
from socket import getfqdn
import subprocess
import sys

import nagios_sender_config as config

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


class NagiosSendConfig(NagiosSender):
    """ Send Nagios configuration """

    def __init__(self):
        NagiosSender.__init__(self)
        self.url = '%s%s' % (config.NAGIOS_HOST, config.CONFIG_URI)
        self.command = config.CMD_GET_CONFIG
        self.shared_key = config.SHARED_KEY


class NagiosSendResults(NagiosSender):
    """ Send Nagios check results """

    def __init__(self):
        NagiosSender.__init__(self)
        self.url = '%s%s' % (config.NAGIOS_HOST, config.RESULTS_URI)
        self.command = config.CMD_GET_RESULTS
        self.shared_key = config.SHARED_KEY


def main():
    """ main function - setup logging and launch instance of NagiosSender """
    logstream = logging.StreamHandler(stream=sys.stdout)
    log_fmt = '%(asctime)s %(levelname)-10s %(threadName)-11s %(message)s'
    formatter = logging.Formatter(log_fmt)

    logstream.setFormatter(formatter)

    logger = logging.getLogger('nagios-sender')
    logger.addHandler(logstream)
    logger.setLevel(config.LOG_LEVEL)

    if len(sys.argv) != 2:
        logging.error('Not enough/too many arguments given.')
        logging.error('%s <send_config|send_results>', sys.argv[0])
        sys.exit(1)
    if sys.argv[1] == 'send_config':
        nagios_instance = NagiosSendConfig()
    elif sys.argv[1] == 'send_results':
        nagios_instance = NagiosSendResults()
    else:
        logging.error("Given argument '%s' is unknown.", sys.argv[1])
        logging.error('%s <send_config|send_results>', sys.argv[0])
        sys.exit(1)

    nagios_instance.run()

if __name__ == '__main__':
    main()
