#!/usr/bin/env python3

import subprocess
import string
import random
import socket
import sys
import logging
import hashlib
sys.path.append('lib') # noqa

from ops.charm import CharmBase, CharmEvents
from ops.framework import EventBase, EventSource, StoredState
from ops.main import main
from ops.model import (
    ActiveStatus,
    WaitingStatus,
    ModelError,
    BlockedStatus,
)
from nrpe.client import NRPEClient
from interfaces import NatsCluster, NatsClient, CAClient

from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization


logger = logging.getLogger(__name__)


class NatsStartedEvent(EventBase):
    pass


class NatsCharmEvents(CharmEvents):
    nats_started = EventSource(NatsStartedEvent)


class NatsCharm(CharmBase):
    on = NatsCharmEvents()
    state = StoredState()

    NATS_SERVICE = 'snap.nats.server.service'
    SNAP_COMMON_PATH = Path('/var/snap/nats/common')
    SERVER_PATH = SNAP_COMMON_PATH / 'server'
    NATS_SERVER_CONFIG_PATH = SERVER_PATH / 'nats.cfg'
    AUTH_TOKEN_PATH = SERVER_PATH / 'auth_secret'
    AUTH_TOKEN_LENGTH = 64
    TLS_KEY_PATH = SERVER_PATH / 'key.pem'
    TLS_CERT_PATH = SERVER_PATH / 'cert.pem'
    TLS_CA_CERT_PATH = SERVER_PATH / 'ca.pem'

    def __init__(self, framework, key):
        super().__init__(framework, key)

        for event in (self.on.install,
                      self.on.start,
                      self.on.upgrade_charm,
                      self.on.config_changed,
                      self.on.cluster_relation_changed,
                      self.on.client_relation_joined):
            self.framework.observe(event, self)

        listen_on_all_addresses = self.model.config['listen-on-all-addresses']
        self.cluster = NatsCluster(self, 'cluster', listen_on_all_addresses)
        self.client = NatsClient(self, 'client', listen_on_all_addresses, self.model.config['client-port'])
        self.state.set_default(is_started=False, auth_token=self.get_auth_token(self.AUTH_TOKEN_LENGTH),
                               use_tls=None, use_tls_ca=None, nats_config_hash=None,
                               client_port=None)

        self.ca_client = CAClient(self, 'ca-client')
        self.framework.observe(self.ca_client.on.tls_config_ready, self)
        self.framework.observe(self.ca_client.on.ca_available, self)

        self.nrpe_client = NRPEClient(self, 'nrpe-external-master')
        self.framework.observe(self.nrpe_client.on.nrpe_available, self)

    def on_install(self, event):
        try:
            core_res = self.model.resources.fetch('core')
        except ModelError:
            core_res = None
        try:
            nats_res = self.model.resources.fetch('nats')
        except ModelError:
            nats_res = None

        cmd = ['snap', 'install']
        # Install the snaps from a resource if provided. Alternatively, snapd
        # will attempt to download it automatically.
        if core_res is not None and Path(core_res).stat().st_size:
            subprocess.check_call(cmd + ['--dangerous', core_res])
        nats_cmd = cmd
        if nats_res is not None and Path(nats_res).stat().st_size:
            nats_cmd += ['--dangerous', nats_res]
        else:
            channel = self.model.config['snap-channel']
            nats_cmd += ['nats', '--channel', channel]
        subprocess.check_call(nats_cmd)
        subprocess.check_call(['snap', 'stop', 'nats', '--disable'])
        self.SERVER_PATH.mkdir(exist_ok=True, mode=0o0700)

    def handle_tls_config(self):
        '''Handle TLS parameters passed via charm config.

        Values are loaded and parsed to provide basic validation and then used to
        determine whether to use TLS in a charm by or not. If TLS is to be used,
        the TLS config content is written to the necessary files.
        '''
        tls_key = self.model.config['tls-key']
        if tls_key:
            load_pem_private_key(tls_key, backend=default_backend())
        tls_cert = self.model.config['tls-cert']
        if tls_cert:
            load_pem_x509_certificate(tls_cert, backend=default_backend())
        tls_ca_cert = self.model.config['tls-ca-cert']
        if tls_ca_cert:
            load_pem_x509_certificate(tls_ca_cert, backend=default_backend())

        self.state.use_tls = tls_key and tls_cert
        self.state.use_tls_ca = bool(tls_ca_cert)
        # Block if one of the values is specified but not the other.
        if bool(tls_key) ^ bool(tls_cert):
            self.status = BlockedStatus('both TLS key and TLS cert must be specified')
        if self.state.use_tls:
            self.TLS_KEY_PATH.write_text(tls_key)
            self.TLS_CERT_PATH.write_text(tls_cert)
            # A CA cert is optional because NATS may rely on system-trusted (core snap) CA certs.
            if self.state.use_tls_ca:
                self.TLS_CA_CERT_PATH.write_text(tls_ca_cert)
                self.client.set_tls_ca(tls_ca_cert)

    def on_nrpe_available(self, event):
        self.reconfigure_nats()

    def on_ca_available(self, event):
        self.reconfigure_nats()

    def on_tls_config_ready(self, event):
        self.TLS_KEY_PATH.write_bytes(self.ca_client.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        self.TLS_CERT_PATH.write_bytes(self.ca_client.certificate.public_bytes(encoding=serialization.Encoding.PEM))
        self.TLS_CA_CERT_PATH.write_bytes(self.ca_client.ca_certificate.public_bytes(encoding=serialization.Encoding.PEM))
        self.reconfigure_nats()

    def generate_content_hash(self, content):
        m = hashlib.sha256()
        m.update(content.encode('utf-8'))
        return m.hexdigest()

    def reconfigure_nats(self):
        logger.info('Reconfiguring NATS')
        self.handle_tls_config()
        ctxt = {
            'client_port': self.model.config['client-port'],
            'cluster_port': self.model.config['cluster-port'],
            'cluster_listen_address': self.cluster.listen_address,
            'client_listen_address': self.client.listen_address,
            'auth_token': self.state.auth_token,
            'peer_addresses': self.cluster.peer_addresses,
            'debug': self.model.config['debug'],
            'trace': self.model.config['trace'],
        }

        # Config is used in priority to using a relation to a CA charm.
        if self.state.use_tls:
            ctxt.update({
                'use_tls': True,
                'tls_key_path': self.TLS_KEY_PATH,
                'tls_cert_path': self.TLS_CERT_PATH,
                'verify_tls_clients': self.model.config['verify-tls-clients'],
                'map_tls_clients': self.model.config['map-tls-clients'],
            })
            if self.state.use_tls_ca:
                ctxt['tls_ca_cert_path'] = self.TLS_CA_CERT_PATH
        elif self.ca_client.is_joined:
            if not self.ca_client.is_ready:
                # TODO: move SAN generation into a separate function
                # Use a reverse resolution for bind-address of a cluster endpoint as a heuristic to
                # determine a common name.
                common_name = socket.getnameinfo((str(self.cluster.listen_address), 0), socket.NI_NAMEREQD)[0]
                san_addresses = set()
                san_addresses.add(str(self.cluster.listen_address))
                san_addresses.add(str(self.cluster.ingress_address))
                san_addresses.add(str(self.client.listen_address))
                for addr in self.client.ingress_addresses:
                    san_addresses.add(str(addr))
                if self.model.config['listen-on-all-addresses']:
                    raise RuntimeError('Generating certificates with listen-on-all-addresses option is not supported yet')
                    # TODO: update with all host interface addresses to implement this for listen-on-all-addresses.
                san_hostnames = set()
                for addr in san_addresses:
                    # May raise gaierror.
                    name = socket.getnameinfo((str(addr), 0), socket.NI_NAMEREQD)[0]
                    san_hostnames.add(name)
                sans = san_addresses.union(san_hostnames)
                self.ca_client.request_server_certificate(common_name, list(sans))
                self.model.unit.status = WaitingStatus('Waiting for TLS configuration data from the CA client.')
                return
            ctxt.update({
                'use_tls': True,
                'tls_key_path': self.TLS_KEY_PATH,
                'tls_cert_path': self.TLS_CERT_PATH,
                'verify_tls_clients': self.model.config['verify-tls-clients'],
                'map_tls_clients': self.model.config['map-tls-clients'],
                'tls_ca_cert_path': self.TLS_CA_CERT_PATH,
            })
            self.client.set_tls_ca(
                self.ca_client.ca_certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8'))

        if self.nrpe_client.is_available:
            check_name = "check_{}".format(self.model.unit.name.replace("/", "_"))
            self.nrpe_client.add_check(command=[
                '/usr/lib/nagios/plugins/check_tcp',
                '-H', str(self.client.listen_address),
                '-p', str(self.model.config['client-port'])
            ], name=check_name)
            self.nrpe_client.commit()

        tenv = Environment(loader=FileSystemLoader('templates'))
        template = tenv.get_template('nats.cfg.j2')
        rendered_content = template.render(ctxt)
        content_hash = self.generate_content_hash(rendered_content)
        old_hash = self.state.nats_config_hash
        if old_hash != content_hash:
            logging.info(f'Config has changed - re-rendering a template to {self.NATS_SERVER_CONFIG_PATH}')
            self.state.nats_config_hash = content_hash
            self.NATS_SERVER_CONFIG_PATH.write_text(rendered_content)
            if self.state.is_started:
                subprocess.check_call(['systemctl', 'restart', self.NATS_SERVICE])
        self.client.expose_nats(auth_token=self.state.auth_token)

        client_port = self.model.config['client-port']
        if (client_port is None or client_port == 0) and (self.state.client_port is not None or len(self.state.client_port) > 0):
            self._close_port(self.state.client_port)
        else:
            port = '{}/tcp'.format(client_port)
            if self.state.client_port is not None and port != self.state.client_port:
                self._close_port(self.state.client_port)
            self._open_port(port)
            self.state.client_port = port

        self.unit.status = ActiveStatus()

    def get_auth_token(self, length=None):
        '''Generate a random auth token.'''
        if not isinstance(length, int):
            raise RuntimeError('invalid length provided for a token')
        alphanumeric_chars = string.ascii_letters + string.digits
        rng = random.SystemRandom()
        return ''.join([rng.choice(alphanumeric_chars) for _ in range(length)])

    def on_start(self, event):
        subprocess.check_call(['snap', 'start', 'nats', '--enable'])
        self.state.is_started = True
        self.on.nats_started.emit()
        self.model.unit.status = ActiveStatus()

    def on_cluster_relation_changed(self, event):
        self.reconfigure_nats()

    def on_client_relation_joined(self, event):
        self.reconfigure_nats()

    def on_config_changed(self, event):
        self.reconfigure_nats()

    def on_upgrade_charm(self, event):
        self.reconfigure_nats()

    def _open_port(self, port):
        subprocess.check_call(['open-port', port])

    def _close_port(self, port):
        subprocess.check_call(['close-port', port])


if __name__ == '__main__':
    main(NatsCharm)
