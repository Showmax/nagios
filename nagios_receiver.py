"""
Copyright (c) 2014, ICFLIX Media FZ LLC All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.

Desc: Receive encrypted check_multi output via HTTP POST and save it for further
processing.
"""
import hashlib
import os
import re
import time
import traceback
import sys

import nagios_receiver_config as config

sys.stdout = sys.stderr

RE_QUERY_STRING = re.compile(r'(?P<query_string>\?.*)$')
RE_FQDN = re.compile(r'^[a-zA-Z0-9]+[a-zA-Z0-9\.\-\_]+[a-zA-Z]+$')

class HttpError(Exception):
    """Abstraction of HTTP Errors."""

    http_codes = {
        200: 'OK',
        400: 'Bad Request',
        403: 'Forbidden',
        404: 'Not Found',
        408: 'Request Timeout',
        411: 'Length Required',
        413: 'Request Entity Too Large',
        415: 'Unsupported Media Type',
        500: 'Internal Server Error',
        501: 'Not Implemented',
    }


class TimeoutException(Exception):
    """Timeout Exception."""
    pass


def ensure_dir(file_name):
    """If directory dirname(file_name) doesn't exist, create it."""
    dir_name = os.path.dirname(file_name)
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

def get_environment_vars(environ):
    """Get environment variables and enforce limits."""
    # Defaults
    env_vars = {
        'uri': '',
        'content_len': 0,
        'content_type': 'unknown',
        'req_method': 'FOO',
    }
    if 'REQUEST_URI' in environ:
        env_vars['uri'] = environ['REQUEST_URI']
    elif 'PATH_INFO' in environ:
        env_vars['uri'] = environ['PATH_INFO']

    if 'CONTENT_LENGTH' in environ:
        try:
            env_vars['content_len'] = int(environ['CONTENT_LENGTH'])
        except ValueError:
            env_vars['content_len'] = 0

    if 'REQUEST_METHOD' in environ:
        env_vars['req_method'] = environ['REQUEST_METHOD']

    if 'CONTENT_TYPE' in environ:
        env_vars['content_type'] = environ['CONTENT_TYPE']

    # Only valid Request Method is POST
    if env_vars['req_method'] != 'POST':
        print "Invalid HTTP Request '%s' method" % env_vars['req_method']
        raise HttpError(501)
    if env_vars['content_type'] != 'text/plain':
        print "Invalid Content-Type '%s'" % env_vars['content_type']
        raise HttpError(415)
    #  Content-Length is ALWAYS > 0
    if env_vars['content_len'] == 0:
        print "Invalid Content-Length %i" % env_vars['content_len']
        raise HttpError(411)
    # Content-Length is ALWAYS < Content-Legth Limit
    if env_vars['content_len'] > config.CONTENT_LENGTH_MAX:
        print ("Content-Length %.0f exceeds limit %.0f"
               % (env_vars['content_len'], config.CONTENT_LENGTH_MAX))
        raise HttpError(413)

    return env_vars

def get_post_data(fhandle, data_len):
    """Try to read HTTP POST data
    Reason for SIGALRM is client and server can get stuck here. We don't want
    that. Think of it as a defence of server when client is dragging its feet
    with sending data or whatever.
    """
    try:
        post_data = fhandle.read(data_len)
    except TimeoutException:
        print "Failed to read HTTP POST data: %s" % traceback.format_exc()
        raise HttpError(408)

    return post_data

def application(environ, start_response):
    """Whee."""
    try:
        # Preliminary checks and all. Yes, environments DO differ!
        env_vars = get_environment_vars(environ.copy())
        env_vars['uri'] = RE_QUERY_STRING.sub('', env_vars['uri'])
        if env_vars['uri'] == '/health':
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return ['']

        uri_parts = env_vars['uri'].split('/')[1:]
        component = uri_parts[len(uri_parts) - 1]
        if component not in config.COMPONENTS:
            print "Unknown component '%s'" % component
            raise HttpError(404)

        data_raw = get_post_data(environ['wsgi.input'], env_vars['content_len'])
        lines = data_raw.split('\n')

        # The first line is ALWAYS 'CHECKSUM', second is 'FQDN'. If it isn't,
        # then we've either received garbage OR garbage. Hard cheese.
        if len(lines) < 4:
            print "Expected at least 4 lines, parsed %i" % len(lines)
            raise HttpError(400)

        checksum_cli = lines.pop(0).split(':')[1].lstrip(' ')
        remote_key = lines.pop(0).split(':')[1].lstrip(' ')
        if not validate_remote_key(checksum_cli, remote_key):
            print "Invalid key '%s-%s'." % (checksum_cli, remote_key)
            raise HttpError(403)

        rhost = lines.pop(0).split(':')[1].lstrip(' ')
        # garbage in the first item
        _ = lines.pop(0)
        checksum_srv = hashlib.sha256('\n'.join(lines)).hexdigest()
        if checksum_cli != checksum_srv or not RE_FQDN.search(rhost):
            print ("Either checksum '%s' or hostname '%s' don't match."
                   % (checksum_srv, rhost))
            raise HttpError(400)

        if config.COMPONENTS[component] == 'config':
            return save_config(environ, start_response, lines, rhost)
        elif config.COMPONENTS[component] == 'result':
            return save_results(environ, start_response, lines, rhost)
        else:
            print "Unknown action '%s' - this should never happen." % component
            raise HttpError(501)

    except HttpError as exception:
        print traceback.format_exc()
        response = '%s %s' % (exception.args[0],
                              exception.http_codes[exception.args[0]])
        start_response(response, [('Content-Type', 'text/plain')])
        return ['']
    except Exception as exception:
        print traceback.format_exc()
        start_response('500 Internal Server Error',
                       [('Content-Type', 'text/plain')])
        return ['']

def save_config(environ, start_response, lines, rhost):
    """Config files will be stored in <CFG_DIR> as 'FQDN.cfg'. We don't care
    about over-writing files, or do we?
    Since this will be multi-threaded, we should utilize .lock,
    shouldn't we?
    """
    cfg_file = '%s/%s.cfg' % (config.CFG_DIR, rhost)
    write_lines_to_file(cfg_file, lines)
    start_response('200 OK', [('Content-Type', 'plain/text')])
    return ['']

def save_results(environ, start_response, lines, rhost):
    """Save results in <RESULTS_DIR> as 'FQDN.<timestamp>'.
    Create '<FQDN>.<timestamp>.ok' once the file is written.
    """
    results_file = '%s/%s.%i' % (config.RESULTS_DIR, rhost, int(time.time()))
    write_lines_to_file(results_file, lines)
    start_response('200 OK', [('Content-Type', 'plain/text')])
    return ['']

def validate_remote_key(checksum, remote_key):
    """Validate remote key."""
    local_key = hashlib.sha256(
        '%s%s' % (checksum, config.SHARED_KEY)).hexdigest()
    if remote_key != local_key:
        return False
    else:
        return True

def write_lines_to_file(file_name, lines):
    """Write given lines into given file.
    Raise exception if it takes longer than 10s to write file.
    """
    fhandle = None
    try:
        ensure_dir(file_name)
        with open(file_name, 'w+') as fhandle:
            fhandle.write('\n'.join(lines))
            fhandle.close()

        open('%s.ok' % (file_name), 'w').close()
    except Exception as exception:
        print traceback.format_exc()
        # If fhandle is open, try to close it
        if fhandle:
            fhandle.close()

        # Report risen exception back
        raise exception


if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    srv = make_server('localhost', 8080, application)
    srv.serve_forever()
