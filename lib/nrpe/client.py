import logging
import os
import subprocess
from typing import List

import yaml

from ops.framework import EventBase, EventSource, EventsBase, StoredState
from ops.framework import Object

logger = logging.getLogger(__name__)

class NRPEAvailable(EventBase):
    pass


class NRPEClientEvents(EventsBase):
    nrpe_available = EventSource(NRPEAvailable)


class NRPEClient(Object):
    on = NRPEClientEvents()
    state = StoredState()

    nrpe_confdir = '/etc/nagios/nrpe.d'
    nagios_exportdir = '/var/lib/nagios/export'
    check_template = """
#---------------------------------------------------
# This file is Juju managed
#---------------------------------------------------
command[%(check_name)s]=%(command)s
"""
    service_template = ("""
#---------------------------------------------------
# This file is Juju managed
#---------------------------------------------------
define service {
    use                             active-service
    host_name                       %(hostname)s
    service_description             %(hostname)s[%(check_name)s] """
                        """%(description)s
    check_command                   check_nrpe!%(check_name)s
    servicegroups                   %(servicegroup)s
}
""")

    def __init__(self, charm, relation_name='nrpe-external-master'):
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        self.state.set_default(checks={}, dirty=False, nrpe_ready=False)

        self.framework.observe(charm.on[relation_name].relation_changed, self.on_relation_changed)

    @property
    def is_joined(self):
        return self.framework.model.get_relation(self._relation_name) is not None

    @property
    def is_available(self):
        return self.state.nrpe_ready

    def add_check(self, command: List[str], name: str, description: str = None, hostname: str = None):
        """
        Register a new check to be executed by NRPE.
        Call NRPEClient.commit() to save changes.
        If a check with the same name already exists, it will by updated.
        :param command: A string array containing the command to be executed
        :param name: Human readable name for the check
        :param description: A short description of the check
        :param hostname: Unit hostname. Defaults to a combination of nagios_context and unit name
        """
        nagios_context = self.model.config['nagios_context']
        nagios_servicegroups = self.model.config.get('nagios_servicegroups') or nagios_context
        unit_name = self.model.unit.name.replace("/", "_")
        hostname = hostname or f"{nagios_context}-{unit_name}"
        if not description:
            description = f'{name} {unit_name}'

        new_check = {
            'command': command,
            'description': description,
            'hostname': hostname,
            'servicegroup': nagios_servicegroups,
        }

        if name not in self.state.checks or self.state.checks[name] != new_check:
            self.state.dirty = True
            self.state.checks[name] = new_check

    def remove_check(self, name: str):
        self.state.checks.pop(name, None)

    def commit(self):
        """Commit checks to NRPE and Nagios"""
        if not self.state.dirty:
            logger.info('Skipping NRPE commit as nothing changed')
            return

        if not self.state.nrpe_ready:
            logger.info('NRPE relation is not ready')
            return

        self._write_check_files()
        self._publish_to_nagios()
        subprocess.check_call(['systemctl', 'restart', 'nagios-nrpe-server'])
        self.state.dirty = False
        logger.info(f'Successfully updated NRPE checks: {", ".join(c for c in self.state.checks)}')

    def _write_check_files(self):
        """Register the new checks with NRPE and place their configuration files in the appropriate locations"""
        for check_name in self.state.checks:
            check = self.state.checks[check_name]

            check_filename = os.path.join(self.nrpe_confdir, f'{check_name}.cfg')
            check_args = {
                'check_name': check_name,
                'command': ' '.join(check['command'])
            }
            with open(check_filename, 'w') as check_config:
                check_config.write(self.check_template % check_args)

            service_filename = os.path.join(self.nagios_exportdir, 'service__{}_{}.cfg'.format(check['hostname'], check_name))
            service_args = {
                'hostname': check['hostname'],
                'description': check['description'],
                'check_name': check_name,
                'servicegroup': check['servicegroup']
            }
            with open(service_filename, 'w') as service_config:
                service_config.write(self.service_template % service_args)

    def _publish_to_nagios(self):
        """Publish check data on the monitors relation"""
        rel = self.framework.model.get_relation(self._relation_name)
        rel_data = rel.data[self.model.unit]
        rel_data['version'] = '0.3'

        nrpe_monitors = {}
        for check_name in self.state.checks:
            nrpe_monitors[check_name] = {'command': check_name}

        rel_data['monitors'] = yaml.dump({"monitors": {"remote": {"nrpe": nrpe_monitors}}})

    def on_relation_changed(self, event):
        if not self.state.nrpe_ready:
            self.state.nrpe_ready = True
            self.on.nrpe_available.emit()

