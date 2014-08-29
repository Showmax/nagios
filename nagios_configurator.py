#!/usr/bin/python2.7
"""
Copyright (c) 2014, ICFLIX Media FZ LLC All rights reserved.
Use of this source code is governed by a BSD-style license that can be
found in the LICENSE file.

Desc: Generate Nagios configuration from given file, resp. from check_multi.
"""
import logging
import logging.handlers
import json
import os.path
import re
import sys
import yaml

from nagios_to_yaml import NagiosToYaml

ICINGA_DIR = "/etc/icinga"
LOG_FORMAT = '%(asctime)s %(levelname)-10s %(message)s'

MACHINEDB_FILE = "/etc/icinga/machines.json"
NAGIOS_DEFS_FILE = "/etc/icinga/nagios.yml"
NAGIOS_TKEYS = [
        "commands",
        "contacts",
        "contactgroups",
        "datacenters",
        "hostgroups",
        "hosts",
        "services"
        ]

STAGING_DOMAIN = "icflix.io"
# 7 minutes
SVC_FRESHNESS_THRESHOLD = 420

# Make sure Nagios knows all Hosts in MachineDB
#  -> <FQDN>.cfg must exist for each and every Host in MDB
# Re-Generate hostgroups
# Re-Generate contacts
# Re-Generate contactsgroups
# Re-Generate commands
class NagiosConfigGenerator(object):
    """ Generate Nagios Configuration for *ONE* Host from given file. """

    def __init__(self):
        self.machine_db = None
        self.nagios_db = None
        self.load_machine_db()
        self.load_nagios_definitions()
        self.mdb_to_nagios()

    def add_datacenter_to_nagios(self, dct_dict):
        """ Add given Datacenter to Nagios. If given Datacenter is already
        known, merge in attributes/values, but don't over-ride Nagios ones.
        """
        nagios_dcs = self.nagios_db["datacenters"]
        dct_name = dct_dict.pop("host_name")
        if dct_name not in nagios_dcs.keys():
            nagios_dcs[dct_name] = {}

        nagios_dct = nagios_dcs[dct_name]
        if "hostgroups" not in nagios_dct.keys():
            nagios_dct["hostgroups"] = list()

        nagios_dct["hostgroups"].append("datacenter")
        if "host" not in nagios_dct.keys():
            nagios_dct["host"] = {}

        for attr in dct_dict.keys():
            if attr in nagios_dct["host"].keys():
                # Don't over-ride Nagios definitions
                continue

            nagios_dct["host"][attr] = dct_dict[attr]

    def add_host_to_nagios(self, host_dict, is_lxc):
        """ Add given Host to Nagios. If given Host is already known, merge in
        values, but don't over-ride Nagios ones.
        """
        nagios_hosts = self.nagios_db["hosts"]
        hostname = host_dict.pop("host_name")
        if hostname not in nagios_hosts.keys():
            nagios_hosts[hostname] = {}

        nagios_host = nagios_hosts[hostname]
        if "hostgroups" not in nagios_host.keys():
            nagios_host["hostgroups"] = list()

        auto_hostgroup = self.get_auto_hostgroup(hostname)
        nagios_host["hostgroups"].append(auto_hostgroup)
        if is_lxc == True:
            nagios_host["hostgroups"].append("lxc")

        if "_DOMAIN" in host_dict.keys() \
                and host_dict["_DOMAIN"] == STAGING_DOMAIN:
            nagios_host["hostgroups"].append("stage")

        if "host" not in nagios_host.keys():
            nagios_host["host"] = {}

        for attr in host_dict.keys():
            if attr in nagios_host["host"].keys():
                # Don't over-ride Nagios definitions
                continue

            nagios_host["host"][attr] = host_dict[attr]

    def add_services_to_host(self, nagios_host, ext_svcs):
        """ Add (external) service definition to Nagios """
        if "services" not in nagios_host.keys():
            nagios_host["services"] = {}

        nagios_svcs = nagios_host["services"]
        for svc_key in ext_svcs["services"].keys():
            if svc_key not in nagios_svcs.keys():
                nagios_svcs[svc_key] = {}

            nagios_svc = nagios_svcs[svc_key]
            for attr in ext_svcs["services"][svc_key].keys():
                if attr in nagios_svc.keys():
                    continue

                nagios_svc[attr] = ext_svcs["services"][svc_key][attr]

    def ensure_host_definitions(self):
        """ Ensure Nagios knows all Hosts defined in MDB. This is required in
        order to re-generate Hostgroups, because it could easilly happen Nagios
        wouldn't know Host(s) in hostgroups.
        """
        for host_key in self.nagios_db["hosts"].keys():
            host_dict = self.nagios_db["hosts"][host_key]
            host_dict["host"]["host_name"] = host_key
            self.ensure_host_definition(host_dict)

    def ensure_host_definition(self, host_dict):
        """ Ensure file with Host definition exists """
        if host_dict is None:
            return (-1)

        host_file = "%s/objects/host_%s.cfg" % (ICINGA_DIR,
                host_dict["host"]["host_name"])
        if os.path.exists(host_file):
            #logging.debug("File '%s' exists.", host_file)
            return 1

        fhandle = open(host_file, "w+")
        self.write_definition(fhandle, "host", host_dict["host"])

        if "services" not in host_dict:
            host_dict["services"] = {}

        dummy_svc = dict()
        dummy_svc["active_checks_enabled"] = 1
        dummy_svc["check_command"] = "return-ok"
        dummy_svc["check_interval"] = 20
        dummy_svc["host_name"] = host_dict["host"]["host_name"]
        dummy_svc["use"] = "generic-service"
        host_dict["services"]["dummy-ok"] = dummy_svc

        for service_key in host_dict["services"].iterkeys():
            service_copy = host_dict["services"][service_key]
            service_copy["service_description"] = service_key
            self.write_definition(fhandle, "service",
                    service_copy)
            del service_copy

        fhandle.close()
        return 0

    def finish_host_definition(self, host_dict, hostname):
        """ Add/over-ride attributes in Host definition """
        if hostname not in self.nagios_db["hosts"].keys():
            return

        if "host" not in self.nagios_db["hosts"][hostname].keys():
            return

        for attr in self.nagios_db["hosts"][hostname]["host"].keys():
            host_dict[attr] = self.nagios_db["hosts"][hostname]["host"][attr]

    def get_auto_hostgroup(self, hostname):
        """ Determine automatic Nagios hostgroup """
        auto_hostgroup = hostname.split(".")[0]
        auto_hostgroup = re.sub(r"(\d+$|\d+[a-z]+)$", r"", auto_hostgroup)
        return auto_hostgroup

    def get_host_dict(self, hostname, machine_ip, ssh_port, parents):
        """ Create Nagios 'host' as a dictionary from given params.
        Parents is expected to be either None or a list.
        """
        host_dict = {}
        host_dict["use"] = "generic-host"
        host_dict["host_name"] = hostname
        host_dict["address"] = machine_ip
        if parents is not None:
            host_dict["parents"] = ",".join(parents)

        if ssh_port is not None:
            host_dict["_SSH_PORT"] = ssh_port

        splitted = hostname.split(".")
        host_dict["_SHORTNAME"] = ".".join(splitted[:len(splitted)-2])
        host_dict["_DOMAIN"] = ".".join(splitted[len(splitted)-2:])
        return host_dict

    def get_padding(self, padding_len):
        """ Return padding :) """
        padding = ""
        while padding_len > 0:
            padding += " "
            padding_len -= 1

        return padding

    def get_ssh_port(self, machine_obj, is_lxc):
        """ Determine SSH port for given Machine """
        ssh_port = 22
        if is_lxc == False:
            return ssh_port

        if "ports" not in machine_obj.keys():
            # Ehm, this is a bit inconclusive, isn't it?
            return ssh_port

        for port_cfg in machine_obj["ports"]:
            # dict is expected here
            if "private_port" not in port_cfg.keys():
                continue

            if int(port_cfg["private_port"]) == 22:
                ssh_port = int(port_cfg["public_port"])

        return ssh_port

    def load_machine_db(self):
        """ Just loads machine DB from JSON """
        with open(MACHINEDB_FILE, "r") as fhandle:
            self.machine_db = json.load(fhandle)["machines"]
            fhandle.close()

    def load_nagios_definitions(self):
        """ Load Nagios definitions from YAML """
        with open(NAGIOS_DEFS_FILE, "r") as fhandle:
            self.nagios_db = yaml.load(fhandle)
            fhandle.close()

        # Make nagios_db sane
        for top_key in NAGIOS_TKEYS:
            if top_key in self.nagios_db.keys():
                continue

            self.nagios_db[top_key] = {}

        if "passive" not in self.nagios_db["services"].keys():
            self.nagios_db["services"]["passive"] = {}

        if "active" not in self.nagios_db["services"].keys():
            self.nagios_db["services"]["active"] = {}

    def import_config(self, services_cfg):
        if not os.path.exists(services_cfg):
            logging.error("Given file '%s' doesn't exist.", services_cfg)
            return False

        hostname = os.path.basename(services_cfg).replace(".cfg", "")
        if hostname == "":
            logging.error("I have empty hostname! :-(")
            return False

        nagios_host = None
        for host_key in self.nagios_db["hosts"].keys():
            if hostname == host_key:
                nagios_host = self.nagios_db["hosts"][host_key]
                break

        if nagios_host is None:
            logging.error("Machine %s not found in Nagios/MDB.", hostname)
            return False

        logging.info("FQDN: %s", hostname)
        logging.info("IP: %s", nagios_host["host"]["address"])
        logging.info("SSH: %s", nagios_host["host"]["_SSH_PORT"])
        logging.info("Hostgroups: %s", nagios_host["hostgroups"])

        nag2yaml = NagiosToYaml()
        nag2yaml.parse_nagios_config(services_cfg)
        ext_services = nag2yaml.nagios_cfg

        for extsvc_key in ext_services["services"].keys():
            ext_service = ext_services["services"][extsvc_key]
            if "stage" in nagios_host["hostgroups"]:
                ext_service["use"] = "stage-service"
            else:
                ext_service["use"] = "generic-service"

            ext_service["check_freshness"] = 1
            ext_service["active_checks_enabled"] = 0
            ext_service["passive_checks_enabled"] = 1
            ext_service["freshness_threshold"] = SVC_FRESHNESS_THRESHOLD
            ext_service["check_command"] = "check_dummy_4p!2 \"check is stale\""
            if extsvc_key not in self.nagios_db["services"]["passive"].keys():
                continue

            # Over-ride attributes from ['services']['passive']
            svc_nagios = self.nagios_db["services"]["passive"][extsvc_key]
            for attr in svc_nagios.keys():
                ext_service[attr] = svc_nagios[attr]

        self.add_services_to_host(nagios_host, ext_services)
        host_file = "%s/objects/host_%s.cfg" % (ICINGA_DIR, hostname)
        with open(host_file, "w+") as fhandle:
            host_copy = nagios_host["host"].copy()
            host_copy["host_name"] = hostname
            self.write_definition(fhandle, "host", host_copy)
            for svc_key in nagios_host["services"].keys():
                service_copy = nagios_host["services"][svc_key].copy()
                service_copy["service_description"] = svc_key
                self.write_definition(fhandle, "service", service_copy)

            fhandle.close()

        return True

    def mdb_to_nagios(self):
        """ Sync Nagios YAML with MDB """
        for host_key in self.machine_db.keys():
            hostname = "%s.icflix.com" % (host_key)
            mdb_host = self.machine_db[host_key]
            if "datacenter" in mdb_host.keys() \
                    and "provider" in mdb_host.keys():
                dct_name = "%s.%s" % (mdb_host["datacenter"],
                        mdb_host["provider"])
                dct_dict = self.get_host_dict(dct_name, "localhost", None, None)
                dct_dict["use"] = "generic-datacenter"
                dct_dict.pop("_SHORTNAME")
                dct_dict.pop("_DOMAIN")
                self.add_datacenter_to_nagios(dct_dict)
                parents = [dct_name]
            else:
                parents = None

            host_dict = self.get_host_dict(hostname, mdb_host["ip"], 22, parents)
            self.add_host_to_nagios(host_dict, False)
            if "lxc" not in mdb_host.keys():
                continue

            for lxc_key in mdb_host["lxc"].keys():
                ssh_port = self.get_ssh_port(mdb_host["lxc"][lxc_key], True)
                lxc_dict = self.get_host_dict(lxc_key, mdb_host["ip"],
                        ssh_port, [hostname])
                self.add_host_to_nagios(lxc_dict, True)

    def print_definition(self, definition_str, some_dict):
        """ Print host definition """
        stuffing_len = 0
        dict_keys = some_dict.keys()
        dict_keys.sort()
        # figure-out padding len
        for attribute in dict_keys:
            if len(attribute) > stuffing_len:
                stuffing_len = len(attribute)

        stuffing_len += 1
        print "define %s {" % (definition_str)
        for attribute in dict_keys:
            padding_len = stuffing_len - len(attribute)
            padding = self.get_padding(padding_len)
            print "  %s%s%s" % (attribute, padding, some_dict[attribute])

        print "}\n"

    def run(self, services_cfg):
        """ Go, go, go! """
        if not self.import_config(services_cfg):
            return False

        self.ensure_host_definitions()
        self.write_command_definitions()
        self.write_contact_definitions()
        self.write_contactgroup_definitions()
        self.write_datacenter_definitions()
        self.write_hostgroup_definitions()
        self.write_service_definitions()
        return True

    def write_command_definitions(self):
        """ Write definitions of all commands """
        if "commands" not in self.nagios_db.keys():
            return

        commands_file = "%s/objects/commands.cfg" % (ICINGA_DIR)
        fhandle = open(commands_file, "w+")
        i = 0
        for command in self.nagios_db["commands"].keys():
            cmd_dict = self.nagios_db["commands"][command]
            cmd_dict["command_name"] = command
            self.write_definition(fhandle, "command", cmd_dict)
            i += 1

        fhandle.close()
        logging.info("Written %i 'command' definitions.", i)

    def write_contact_definitions(self):
        """ Write definitions of all contacts """
        if "contacts" not in self.nagios_db.keys():
            return

        contacts_file = "%s/objects/contacts.cfg" % (ICINGA_DIR)
        fhandle = open(contacts_file, "w+")
        i = 0
        for contact in self.nagios_db["contacts"].keys():
            contact_dict = self.nagios_db["contacts"][contact]
            contact_dict["contact_name"] = contact
            self.write_definition(fhandle, "contact", contact_dict)
            i += 1

        fhandle.close()
        logging.info("Written %i 'contact' definitions.", i)

    def write_contactgroup_definitions(self):
        """ Write definitions of all contactgroups """
        cgroups_file = "%s/objects/contactgroups.cfg" % (ICINGA_DIR)
        cgroups = self.nagios_db["contactgroups"]
        fhandle = open(cgroups_file, "w+")
        i = 0
        for cgroup_key in cgroups.keys():
            cgroup_dict = cgroups[cgroup_key]
            cgroup_dict["contactgroup_name"] = cgroup_key
            self.write_definition(fhandle, "contactgroup", cgroup_dict)
            i += 1

        fhandle.close()
        logging.info("Written %i 'contactgroup' definitions.", i)

    def write_datacenter_definitions(self):
        """ Write definitions for all datacenters """
        dctrs_file = "%s/objects/datacenters.cfg" % (ICINGA_DIR)
        dctrs = self.nagios_db["datacenters"]
        with open(dctrs_file, "w+") as fhandle:
            i = 0
            for dctr_key in dctrs.keys():
                dct_dict = dctrs[dctr_key]["host"].copy()
                dct_dict["host_name"] = dctr_key
                self.write_definition(fhandle, "host", dct_dict)
                i += 1

            fhandle.close()

        logging.info("Written %i 'datacenter' definitions.", i)

    def write_definition(self, fhandle, definition_str, some_dict):
        """ Write Nagios definition into given file pointer """
        stuffing_len = 0
        dict_keys = some_dict.keys()
        dict_keys.sort()
        # figure-out padding len
        for attribute in dict_keys:
            if len(attribute) > stuffing_len:
                stuffing_len = len(attribute)

        stuffing_len += 1
        fhandle.write("define %s {\n" % (definition_str))
        for attribute in dict_keys:
            padding_len = stuffing_len - len(attribute)
            padding = self.get_padding(padding_len)
            fhandle.write("  %s%s%s\n" % (attribute, padding,
                some_dict[attribute]))

        fhandle.write("}\n\n")

    def write_hostgroup_definitions(self):
        """ Write hostgroup definitions """
        hosts = self.nagios_db["hosts"]
        hostgroups = self.nagios_db["hostgroups"]

        for host in hosts.keys():
            if "hostgroups" not in hosts[host].keys():
                continue

            for hostgroup in hosts[host]["hostgroups"]:
                if hostgroup not in hostgroups.keys():
                    hostgroups[hostgroup] = {}

                # add 'members' attribute if hostgroup doesn't have any
                if "members" not in hostgroups[hostgroup].keys():
                    hostgroups[hostgroup]["members"] = list()

                if host in hostgroups[hostgroup]["members"]:
                    continue

                hostgroups[hostgroup]["members"].append(host)

        dctrs = self.nagios_db["datacenters"]
        for dctr in dctrs.keys():
            if "hostgroups" not in dctrs[dctr].keys():
                continue

            for hostgroup in dctrs[dctr]["hostgroups"]:
                if hostgroup not in hostgroups.keys():
                    hostgroups[hostgroup] = {}

                # add 'members' attribute if hostgroup doesn't have any
                if "members" not in hostgroups[hostgroup].keys():
                    hostgroups[hostgroup]["members"] = list()

                if dctr in hostgroups[hostgroup]["members"]:
                    continue

                hostgroups[hostgroup]["members"].append(dctr)

        hgroups_file = "%s/objects/hostgroups.cfg" % (ICINGA_DIR)
        fhandle = open(hgroups_file, "w+")
        i = 0
        for hgrp_key in hostgroups.keys():
            hostgroup = hostgroups[hgrp_key]
            if "members" in hostgroup.keys():
                if len(hostgroup["members"]) < 1:
                    # I guess Nagios wouldn't like empty members
                    hostgroup.pop("members")
                else:
                    # Yes, let's change 'list' to 'string' and make it easy on
                    # printer
                    hostgroup["members"] = ",".join(hostgroup["members"])

            hostgroup["hostgroup_name"] = hgrp_key
            self.write_definition(fhandle, "hostgroup", hostgroup)
            i += 1

        fhandle.close()
        logging.info("Written %i 'hostgroup' definitions.", i)

    def write_service_definitions(self):
        """ Write service definitons """
        if "active" not in self.nagios_db["services"].keys():
            return

        services_file = "%s/objects/services.cfg" % (ICINGA_DIR)
        fhandle = open(services_file, "w+")
        i = 0
        for svc_key in self.nagios_db["services"]["active"].keys():
            service = self.nagios_db["services"]["active"][svc_key]
            service["service_description"] = svc_key
            if "use" not in service.keys():
                service["use"] = "generic-service"

            self.write_definition(fhandle, "service", service)
            i += 1

        fhandle.close()
        logging.info("Written %i 'service' definitions.", i)

def convert_nagios_config():
    """ Convert given Nagios config into YAML """
    if len(sys.argv) != 4:
        logging.error("Expected %i arguments, %i given.", 3, len(sys.argv) - 1)
        sys.exit(1)

    nagios_to_yaml = NagiosToYaml()
    nagios_to_yaml.parse_nagios_config(sys.argv[2])
    nagios_to_yaml.write_to_yaml(sys.argv[3])

def import_remote_config():
    """ Imports config sent from Remote Host """
    if len(sys.argv) < 3:
        logging.error("Expected %i arguments, %i given.", 2, len(sys.argv) - 1)
        sys.exit(1)

    cfg_file = sys.argv[2]
    config_generator = NagiosConfigGenerator()
    retval = config_generator.run(cfg_file)
    if retval == True:
        logging.info("Will remove '%s'.", cfg_file)
        os.remove(cfg_file)
        os.remove("%s.ok" % (cfg_file))
        print "* run % icinga -v /etc/icinga/icinga.cfg; before reload!"
        print "* don't forget to commit your changes"

def main():
    """ main """
    logging.basicConfig(format=LOG_FORMAT)
    logging.getLogger().setLevel(logging.INFO)
    if len(sys.argv) < 2:
        logging.error("Not enough arguments given.")
        print_help()
        sys.exit(1)

    action = sys.argv[1]
    if action == "help":
        print_help()
    elif action == "import":
        import_remote_config()
    elif action == "regen":
        regenerate_nagios_config()
    elif action == "convert":
        convert_nagios_config()
    else:
        logging.error("Invalid parameter '%s'.", action)
        sys.exit(1)

def print_help():
    """ Print help """
    print "%s <action> [params]" % (sys.argv[0])
    print ""
    print "Actions and params:"
    print " convert <src> <tgt> - convert Nagios config(src) to YAML(tgt)"
    print ""
    print " import <path_to_cfg> - import configuration from remote Host"
    print ""
    print "NOTE: It's possible for 'regen' to create inconsistent Nagios"
    print "      configuration! Use with care!"
    print " regen <what>        - regenerates given definitions"
    print "       commands      - command definitons"
    print "       contacts      - contact definitions"
    print "       contactgroups - contactgroup definitions"
    print "       datacenters   - datacenter definitions"
    print "       hostgroups    - hostgroup definitions"
    print "       services      - (active) service definitions"

def regenerate_nagios_config():
    """ Regenerate part of Nagios config """
    if len(sys.argv) < 3:
        logging.error("Expected %i parameters, %i given.", 2, len(sys.argv) - 1)
        sys.exit(1)

    config_generator = NagiosConfigGenerator()
    config_generator.ensure_host_definitions()
    what = sys.argv[2]
    if what == "commands":
        config_generator.write_command_definitions()
    elif what == "contacts":
        config_generator.write_contact_definitions()
    elif what == "contactgroups":
        config_generator.write_contactgroup_definitions()
    elif what == "datacenters":
        config_generator.write_datacenter_definitions()
    elif what == "hostgroups":
        config_generator.write_hostgroup_definitions()
    elif what == "services":
        config_generator.write_service_definitions()
    else:
        logging.error("Unknown parameter '%s'.", what)
        sys.exit(1)

if __name__ == "__main__":
    main()
