# Nagios - push model

Code is documentation, therefore I urge you study the code as well.

Reasons for push model:
  1. Nagios can process only so many active service checks.
  2. It's rather cumbersome to execute these checks securely on remote hosts.
  3. It's even more cumbersome to execute checks on hosts behind NAT/firewall.

Therefore, it seems better to switch model from poll(active service checks) to push(passive service checks) since all monitored hosts can reach Nagios and Nagios doesn't have to reach monitored hosts. Also, processing of passive checks, resp. results, is less demanding than scheduling and executing active service checks.

Nagios push model consists of the following components:

  * Configurator
  * Receiver
  * Sender

External requirements are:

  * Nagios configuration in YAML
  * Machine Database


## Configurator

Configurator takes care of Nagios configuration. It utilizes MDB and Nagios configuration in YAML. Almost nothing in Nagios should be configured by editing 'objects/*.cfg' files directly with the exception of host/service templates, timeperiods and ido2db configuration. Anything else is/should be generated from YAML file!

Use-cases of Configurator are:

  * convert Nagios configuration file into YAML
  * generate parts of Nagios configuration, eg. commands, contact groups,
    host groups, services etc.
  * process configuration of remote Host

Requires:

  * Machine Database JSON file(cron job to sync MDB is included in debpkg!)
  * Nagios configuration in YAML


## Sender

Sender is a Python script which does two things:

  * sends output, resp. check results, from `check_multi` to remote Nagios server
  * sends Nagios configuration produced by `check_multi` to remote Nagios server

This is done by HTTP POST and data are obfuscated. "Magic" URLs are being used to distinguish between 'configuration' and 'results'. **Sender ~~should~~ must be executed as user 'nagios'!**

Debian package is self-contained, although configuration file could be distributed separately, eg. via Puppet. Results are being sent every minute and job is scheduled and executed by cron.

## Receiver

Receiver consists of a small uwsgi application and simple shell script.

uwsgi application stores received configurations and results into separate directories. An 'ok' file is created once all data has been written.

Shell script is executed via runit and is an endless loop with 30s sleep intervals. It takes all files with check results from remote hosts and `cat` it to `check_multi` for processing. Processed files are removed once they have been passed to `check_multi`.

## How-to

### Add a new Host into Nagios

On remote Host 'www.example.org'

```shell
# package icflix-nagios-sender must be installed
dpkg -l | grep icflix-nagios-sender
ii  icflix-nagios-sender
# as user Nagios
su -l nagios
# send configuration to Icinga
python /opt/icflix/nagios/bin/nagios_sender.py send_config
```

Now, on Host running Icinga

```shell
cd /opt/icflix/nagios/bin/
python nagios_configurator.py import /var/lib/nagios/remoteconfigs/www.example.org.cfg
2014-02-27 14:00:21,824 INFO       FQDN: www.example.org
2014-02-27 14:00:21,824 INFO       IP: 1.2.3.4
2014-02-27 14:00:21,824 INFO       SSH: 22
2014-02-27 14:00:21,824 INFO       Hostgroups: [u'www']
2014-02-27 14:00:21,824 INFO       Processed 60 lines.
2014-02-27 14:00:21,837 INFO       Written 12 'command' definitions.
2014-02-27 14:00:21,837 INFO       Written 3 'contact' definitions.
2014-02-27 14:00:21,837 INFO       Written 3 'contactgroup' definitions.
2014-02-27 14:00:21,837 INFO       Written 9 'datacenter' definitions.
2014-02-27 14:00:21,838 INFO       Written 65 'hostgroup' definitions.
2014-02-27 14:00:21,839 INFO       Written 40 'service' definitions.
2014-02-27 14:00:21,839 INFO       Will remove '/var/lib/nagios/remoteconfigs/www.example.org.cfg'.
* run % icinga -v /etc/icinga/icinga.cfg; before reload!
* don't forget to commit your changes

# make sure configuration is OK and reload Icinga
icinga -v /etc/icinga/icinga.cfg
service icinga reload
```


### Remove Host from Nagios

To remove Host configuration from Icinga:

1. Find Host's configuration file in '/etc/icinga/objects'
  * configuration file should have name 'host_<FQDN>.cfg'
2. Remove Host's configuration file
3. Some Nagios configuration must be re-generated
  * This is done via `nagios_configurator.py regen <WHAT>`
  * at minimum, you have to regenerate 'hostgroups' and probably 'services'
4. Verify Nagios configuration is OK `icinga -v /etc/icinga/icinga.cfg`
5. Reload Nagios


### Add new active service check, contact, command etc.

Edit '/etc/icinga/nagios.yml' and add desired component, eg. new command or contact. Then use Configurator to regenerate part, or parts, of Nagios configuration in question.

### Re-send configuration from remote Host

1. SSH to remote Host
2. switch to nagios user - `su -l nagios`
3. execute Sender - `/opt/icflix/nagios/bin/nagios_sender.py send_config`


## Technical mumbo jumbo

### Payload obfuscation

Whole payload is being scrambled by Vigenere cipher. This cipher doesn't require any Python library and is easy to use. Of course, it's a rather weak cipher, but it can be replaced by any other cipher.

Reason to scramble data is not only to hide it from prying eyes, but to prove client is "entitled" to communicate with Nagios by knowing shared secret. Of course, it would be more secure to use some asymetric encryption instead and it eventually can be done.

### Message format

Message format is rather simple:

```shell
CHECKSUM: $SHA256_OF_DATA
FQDN: $FQDN
---
$DATA
```

* CHECKSUM - SHA256 checksum of DATA being sent
* FQDN - FQDN of Sender, resp. Node sending data
* DATA - output from check_multi


### Nagios configuration in YAML, structure of YAML

Nagios configuration has been converted into YAML, resp. Configurator expects it to be this way. What follows is expected YAML structure.

```yaml
commands:
  my_command: { kv_command_definition }
contactgroups:
  my_contactgroup: { kv_contactgroup_definition }
contacts:
  my_contact: { kv_contact_definition }
hostgroups:
  my_hostgroup: { kv_hostgroup_definition }
hosts:
  my_host:
    host: { kv_for_host_definition }
    hostgroups: [ list_of_hgroup_names ]
    services: { dict_of_services_for_host }
services:
  active:
    my_active_check { kv_service_definition }
  passive:
    my_passive_check { kv_service_definition }
```

For example, you shouldn't need to define any hosts unless you want to either over-ride something or add host specific macro. List of hosts, IP addresses, SSH port etc. is taken from MDB. The same goes for passive service checks and perhaps even hostgroups. On the other hand, commands, active service checks, contacts and contact groups can't be made out of thin air and must be defined.

### Structure of Nagios configuration files

Nagios configuration has been split into multiple files. Of course, there are some drawbacks, although they're easy to over-come, like you have to remeber names of definitions. On the other hand, one mamoth file with everything in it seemed to be unmaintainable.

List of files generated from MDB/YAML by Configurator:

* `commands.cfg` - command definitions
* `contactgroups.cfg` - contact group definitions
* `contacts.cfg` - contact definitions
* `datacenters.cfg` - datacenter(host) definitions
* `hostgroups.cfg` - host group definitions
* `host_www.example.org.cfg` - definitions for Host 'www.example.org' including
  host and (passive) service check definitions
* `services.cfg` - (active) service checks definitions

You shouldn't touch these files by hand!
