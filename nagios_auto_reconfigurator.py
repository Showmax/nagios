#!/usr/bin/python
"""
Copyright (c) 2015, ICFLIX Media FZ LLC All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.

Desc: Nagios auto-reconfigurator meant to be executed from cron
"""
import argparse
import json
import logging
import logging.handlers
import nagios_configurator
import os
import subprocess
from os import listdir
from os.path import isfile, join

ICINGA_BIN = '/usr/sbin/icinga'
ICINGA_CONFIG_PATH = '/etc/icinga/icinga.cfg'
LOG_FORMAT = '%(asctime)s %(levelname)-10s %(message)s'

class IcingaConfigInvalid(Exception):
    """Exception - Icinga configuration is invalid/contains errors."""
    pass

class IcingaReload(Exception):
    """Exception - Failed to reload Icinga."""
    pass

class NagiosAutoReconfigurator(object):
    """Auto-magic reconfigurator of Nagios."""

    def __init__(self):
        """Constructor."""
        self.mdb_file = None
        self.nagios_obj_dir = None
        self.remote_configs_dir = None
        self.nagios_config_regen = False

    def _get_mdb_hosts(self, include_lxc=True):
        """Return set of FQDNs found in MDB including LXCs."""
        mdb_hosts = set()
        fhandle = open(self.mdb_file, 'r')
        json_obj = json.load(fhandle)
        fhandle.close()
        for key in json_obj['machines'].iterkeys():
            if not key.endswith('icflix.com'):
                machine = '%s.icflix.com' % (key)
            else:
                machine = key

            mdb_hosts.add(machine)

            if not include_lxc:
                continue

            if 'lxc' in json_obj['machines'][key]:
                for lxc in json_obj['machines'][key]['lxc'].iterkeys():
                    mdb_hosts.add(lxc)

        return mdb_hosts

    def icinga_reload(self):
        """Reload service Icinga."""
        logging.info('Will reload Icinga')
        proc1 = subprocess.Popen(['/etc/init.d/icinga', 'reload'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = proc1.communicate()
        logging.debug("Icinga reload STDOUT '%s'", out)
        logging.debug("Icinga reload STDERR '%s'", err)
        if err != '':
            logging.error("Failed to reload Icinga STDOUT: '%s'", out)
            logging.error("Failed to reload Icinga STDERR: '%s'", err)
            raise IcingaReload

        if out != "Reloading icinga monitoring daemon configuration "\
                "files: icinga.\n":
            logging.error("Failed to reload Icinga STDOUT: '%s'", out)
            logging.error("Failed to reload Icinga STDERR: '%s'", err)
            raise IcingaReload

        logging.info('Reload OK')

    def icinga_check_config(self):
        """Check whether Icinga's config is OK - no warnings, no errors."""
        logging.info('Will check Icinga config')
        proc1 = subprocess.Popen([ICINGA_BIN, '-v', ICINGA_CONFIG_PATH],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = proc1.communicate()
        logging.debug("Icinga config check STDOUT '%s'", out)
        logging.debug("Icinga config check STDERR '%s'", err)
        if err != '':
            logging.error("STDERR of Icinga config check: '%s'", err)
            raise IcingaConfigInvalid

        summary = {}
        for line in out.splitlines():
            if not line.startswith('Total'):
                continue

            (desc, count) = line.split(':', 1)
            (_, key) = desc.split(' ', 1)
            summary[key.lower()] = int(count)

        if 'warnings' not in summary or 'errors' not in summary:
            logging.error('Failed to parse STDOUT of Icinga config check.')
            raise IcingaConfigInvalid

        if summary['warnings'] > 0 or summary['errors'] > 0:
            logging.error("Icinga config check errors: %i, warnings: %i",
                          summary['errors'], summary['warnings'])
            raise IcingaConfigInvalid

        logging.info('Config OK')

    def import_new_configs(self):
        """Import new configurations from remote Hosts."""
        filenames = [f for f in listdir(self.remote_configs_dir)
                     if isfile(join(self.remote_configs_dir, f))]
        for filename in filenames:
            if not filename.endswith('.ok'):
                continue

            cfg_file = os.path.join(self.remote_configs_dir,
                                    filename.rstrip('.ok'))
            configurator = nagios_configurator.NagiosConfigGenerator()
            if not configurator.import_config(cfg_file):
                logging.error("Processing of '%s' has failed.", cfg_file)
                continue

            del configurator
            self.nagios_config_regen = True
            logging.info("Will remove '%s'.", cfg_file)
            os.remove(cfg_file)
            os.remove(os.path.join(self.remote_configs_dir, filename))

    def purge_old_hosts(self):
        """Purge Hosts which are no longer in MDB."""
        filenames = [f for f in listdir(self.nagios_obj_dir)
                     if isfile(join(self.nagios_obj_dir, f))]
        mdb_hosts = self._get_mdb_hosts()
        for filename in filenames:
            if not filename.startswith('host_') \
                    or not filename.endswith('.cfg'):
                continue

            (_, hostname) = filename.rstrip('.cfg').split('_', 1)
            if hostname in mdb_hosts:
                logging.debug('%s found in MDB', hostname)
                continue

            self.nagios_config_regen = True
            logging.info("%s not found in MDB, removing '%s'.", hostname,
                         os.path.join(self.nagios_obj_dir, filename))
            os.unlink(os.path.join(self.nagios_obj_dir, filename))

    def regenerate_configuration(self):
        """
        Regenerate Nagios configuration - commands, contacts, services etc.
        """
        configurator = nagios_configurator.NagiosConfigGenerator()
        configurator.ensure_host_definitions()
        configurator.write_command_definitions()
        configurator.write_contact_definitions()
        configurator.write_contactgroup_definitions()
        configurator.write_datacenter_definitions()
        configurator.write_hostgroup_definitions()
        configurator.write_service_definitions()
        del configurator

    def run(self):
        """Go, go, go."""
        self.purge_old_hosts()
        self.import_new_configs()
        if self.nagios_config_regen:
            self.regenerate_configuration()
            self.icinga_check_config()
            self.icinga_reload()

def parse_args():
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--mdb-file',
                        dest='mdb_file', type=str, required=True,
                        help='MDB JSON file.')
    parser.add_argument('--nagios-objects-dir',
                        dest='nagios_obj_dir',
                        type=str, default='/etc/icinga/objects',
                        help='Path to directory with Nagios objects')
    parser.add_argument('--remote-configs-dir',
                        dest='remote_configs_dir',
                        type=str, required=True,
                        help=('Path to directory with configs uploaded '
                              'by remote hosts.'))
    parser.add_argument('-v',
                        dest='verbose', action='store_true', default=False,
                        help='Increase logging verbosity')
    return parser.parse_args()

def main():
    """Main."""
    args = parse_args()
    logging.basicConfig(format=LOG_FORMAT)
    log_level = logging.INFO
    if args.verbose:
        log_level = logging.DEBUG

    logging.getLogger().setLevel(log_level)
    reconfigurator = NagiosAutoReconfigurator()
    reconfigurator.mdb_file = args.mdb_file
    reconfigurator.nagios_obj_dir = args.nagios_obj_dir
    reconfigurator.remote_configs_dir = args.remote_configs_dir
    reconfigurator.run()

if __name__ == '__main__':
    main()
