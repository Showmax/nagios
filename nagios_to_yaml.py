"""
Copyright (c) 2014, ICFLIX Media FZ LLC All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.

Desc: Convert Nagios cfg file into YAML
"""
import logging
import logging.handlers
import sys
import re
import yaml

RE_DEFINE = re.compile(r'^define .+{[\s\t]*$')
RE_DEFINE_END = re.compile(r'^[\s\t]*}[\s\t]*$')
RE_ICFLIX = re.compile(r'icflix\.(com|io)$')

ALIASES = {
    'command': 'commands',
    'contact': 'contacts',
    'contactgroup': 'contactgroups',
    'host': 'hosts',
    'hostgroup': 'hostgroups',
    'service': 'services',
}

class NagiosToYaml(object):
    """Convert given Nagios configuration file into YAML."""

    def __init__(self):
        self.nagios_cfg = {}

    def fix_hostname(self, obj):
        """Append .icflix.com to hostnames."""
        if 'host_name' not in obj:
            return

        hosts = obj['host_name'].replace('"', '').split(',')
        i = 0
        while i < len(hosts):
            if not RE_ICFLIX.search(hosts[i]):
                logging.debug('Fixing %s to %s.icflix.com', hosts[i], hosts[i])
                hosts[i] = '%s.icflix.com' % (hosts[i])

            i += 1

        obj['host_name'] = ','.join(hosts)

    def process_object(self, obj):
        """Process parsed object."""
        obj_type = obj.pop('_DEF_TYPE')
        stor_key = ALIASES[obj_type]
        if stor_key not in self.nagios_cfg:
            self.nagios_cfg[stor_key] = {}

        if obj_type == 'service':
            name_key = '_description'
            self.fix_hostname(obj)
            # We have only 'generic-service' anyway -> default
            obj.pop('use')
        elif obj_type == 'host':
            name_key = '_name'
            # This is defined in MachineDB
            obj.pop('address')
            # 'generic-host' will be used by default anyway
            obj.pop('use')
            # 'passive_checks_enabled' will be on by default
            if 'passive_checks_enabled' in obj:
                obj.pop('passive_checks_enabled')
        else:
            name_key = '_name'

        obj_name = None
        for attr in obj.keys():
            if name_key in attr:
                obj_name = obj.pop(attr)
                break

        if obj_name is None:
            # FAIL
            return

        if obj_type == 'host':
            if not RE_ICFLIX.search(obj_name):
                obj_name = '%s.icflix.com' % (obj_name)

            self.nagios_cfg[stor_key][obj_name] = {}
            self.nagios_cfg[stor_key][obj_name]['host'] = obj
        else:
            self.nagios_cfg[stor_key][obj_name] = obj

    def process_hostgroups(self):
        """Put hostgroup name to respective members in 'hosts'."""
        if 'hostgroups' not in self.nagios_cfg:
            return

        hostgroups = self.nagios_cfg['hostgroups']
        for hostgroup in hostgroups.iterkeys():
            if 'members' not in hostgroups[hostgroup]:
                continue

            members = list()
            for member in hostgroups[hostgroup]['members'].split(','):
                fqdn = member
                if not RE_ICFLIX.search(fqdn):
                    fqdn = '%s.icflix.com' % (fqdn)

                if fqdn not in self.nagios_cfg['hosts']:
                    logging.warning('%s(former: %s) not found.', fqdn,
                                    repr(member))
                    members.append(member)
                    continue

                if 'hostgroups' not in self.nagios_cfg['hosts'][fqdn]:
                    self.nagios_cfg['hosts'][fqdn]['hostgroups'] = list()

                self.nagios_cfg['hosts'][fqdn]['hostgroups'].append(hostgroup)

            if len(members) == 0:
                hostgroups[hostgroup].pop('members')
            else:
                hostgroups[hostgroup]['members'] = members

    def parse_nagios_config(self, config_file):
        """Parse Nagios config file and represent it as an object."""
        with open(config_file, 'r') as fhandle:
            lines = fhandle.read().splitlines()

        obj_dict = {}
        i = 0
        for line in lines:
            i += 1
            line = line.rstrip('\n')
            if line == '':
                # Empty line
                continue

            if line.startswith('#'):
                # Line is a comment
                continue

            if RE_DEFINE.match(line):
                obj_dict = None
                obj_dict = {}
                obj_dict['_DEF_TYPE'] = line.split(' ')[1]
            elif RE_DEFINE_END.match(line):
                self.process_object(obj_dict)
                obj_dict = None
            else:
                if obj_dict is None:
                    logging.error('obj_dict is None, line: %i', repr(line))
                    continue

                line = ' '.join(line.split())
                line = line.lstrip(' ')
                line = line.rstrip(' ')
                line = line.lstrip('\t')
                line = line.rstrip('\t')
                splitted = line.split(' ')
                if splitted is None:
                    logging.error('splitted is None, line: %s', repr(line))
                    continue

                obj_dict[splitted[0]] = ' '.join(splitted[1:])

        logging.info('Processed %i lines.', i)
        self.process_hostgroups()

    def write_to_yaml(self, target_file):
        """Write YAML into given file."""
        with open(target_file, 'w+') as fhandle:
            yaml.dump(self.nagios_cfg, fhandle, indent=2)


def main():
    """Main."""
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    convertor = NagiosToYaml()
    convertor.parse_nagios_config(sys.argv[1])
    convertor.write_to_yaml(sys.argv[2])

def print_help():
    """Print-out help text."""
    print 'nagios-to-yaml - convert nagios.cfg into YAML'
    print 'Usage: %s <nagios.cfg> <nagios.yml>' % (sys.argv[0])

if __name__ == '__main__':
    main()
