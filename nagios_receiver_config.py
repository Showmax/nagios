"""Nagios Receiver config."""
SHARED_KEY = ''
CFG_DIR = '/var/lib/nagios/remoteconfigs/'
RESULTS_DIR = '/var/lib/nagios/remoteresults/'

COMPONENTS = {
    'configs': 'config',
    'results': 'result',
}

# Maximum Content-Length 1MB ?
CONTENT_LENGTH_MAX = 1048576
