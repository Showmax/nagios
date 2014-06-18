#!/bin/sh
# 2014/Feb/14 @ Zdenek Styblik <zdenek.styblik@icflix.com>
# Desc: simple script to process Nagios Check Results sent by remote Hosts
RESULTS_DIR="/var/lib/nagios/remoteresults"
CHECK_MULTI="/usr/lib/nagios/plugins/check_multi"

while true; do
    for OK_FILE in "${RESULTS_DIR}/"*.ok; do
        RES_FILE=$(basename -- "${OK_FILE}" ".ok")
        RHOST=$(printf -- "%s" "${RES_FILE}" | sed -r 's@\.[0-9]+$@@')
        # http://my-plugin.de/wiki/projects/check_multi/configuration/options
        su -c "cat -- \"${RESULTS_DIR}/${RES_FILE}\" | \
            \"${CHECK_MULTI}\" \
            -f - \
            -r 8192+8+1 \
            -s HOSTNAME=\"${RHOST}\" \
            -s checkresults_dir=/var/lib/icinga/spool/checkresults/" - nagios
        rm -f -- "${OK_FILE}" "${RESULTS_DIR}/${RES_FILE}"
    done
    sleep 30
done
