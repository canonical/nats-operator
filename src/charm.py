#!/usr/bin/env python3

import subprocess
import string
import random
import sys
import logging
sys.path.append('lib') # noqa

from ops.charm import CharmBase, CharmEvents
from ops.framework import EventBase, EventSource, StoredState
from ops.main import main
from ops.model import (
    ActiveStatus,
    ModelError,
    BlockedStatus,
)
from interfaces import NatsCluster, NatsClient

from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate


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
    TLS_KEY_PATH = SERVER_PATH / 'tls/key.pem'
    TLS_CERT_PATH = SERVER_PATH / 'tls/cert.pem'
    TLS_CA_CERT_PATH = SERVER_PATH / 'tls/ca.pem'

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
                               use_tls=None, use_tls_ca=None, nats_config_hash=None)

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
        # Install the core snap from a resource if provided. Alternatively, snapd
        # will attempt to download it automatically.
        if core_res is not None and Path(core_res).stat().st_size:
            subprocess.check_call(cmd + ['--dangerous', core_res])
        if nats_res is not None and Path(nats_res).stat().st_size:
            nats_cmd = cmd + ['--dangerous', nats_res]
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
            load_pem_x509_certificate(tls_cert, bacend=default_backend())
        tls_ca_cert = self.model.config['tls-ca-cert']
        if tls_ca_cert:
            load_pem_x509_certificate(tls_ca_cert, default_backend())

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

        tenv = Environment(loader=FileSystemLoader('templates'))
        template = tenv.get_template('nats.cfg.j2')
        rendered_content = template.render(ctxt)
        content_hash = hash(rendered_content)
        old_hash = self.state.nats_config_hash
        if old_hash != content_hash:
            logging.info(f'Config has changed - re-rendering a template to {self.NATS_SERVER_CONFIG_PATH}')
            logger.info('')
            self.state.rendered_content_hash = content_hash
            self.NATS_SERVER_CONFIG_PATH.write_text(rendered_content)
            if self.state.is_started:
                subprocess.check_call(['systemctl', 'restart', self.NATS_SERVICE])
        self.client.expose_nats()

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


if __name__ == '__main__':
    main(NatsCharm)
