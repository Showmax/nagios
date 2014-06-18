import logging
from socket import getfqdn

LOG_LEVEL = logging.ERROR
LOG_FILE = "/dev/null"

SHARED_KEY = ""

NAGIOS_HOST = "https://icinga.example.com"
CONFIG_URI = "/configs"
RESULTS_URI = "/results"

CHECK_MULTI_BIN = "/usr/lib/nagios/plugins/check_multi"

CMD_GET_CONFIG = [CHECK_MULTI_BIN,
        "-f",
        "/etc/check_multi",
        "-s",
        "HOSTNAME=\"%s\"" % (getfqdn()),
        "-r",
        "2048" ]
CMD_GET_RESULTS = [CHECK_MULTI_BIN,
        "-f",
        "/etc/check_multi",
        "-r",
        "256" ]
