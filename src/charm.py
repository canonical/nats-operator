#!/usr/bin/env python3

"""Charmed Machine Operator for the NATS."""

from __future__ import annotations

import hashlib
import logging
import random
import socket
import string
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from nats_config import NATS
from nrpe.client import NRPEClient  # noqa: E402
from ops import (
    ConfigChangedEvent,
    EventBase,
    EventSource,
    InstallEvent,
    RelationJoinedEvent,
    StoredState,
)
from ops.charm import CharmBase, CharmEvents, UpgradeCharmEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, ModelError
from relations.caclient_requirer import CAClientRequires, TlsConfigReady
from relations.cluster_peers import NatsCluster
from relations.natsclient_provider import NATSClientProvider

logger = logging.getLogger(__name__)


class NatsStartedEvent(EventBase):
    """NATS Started Event."""

    pass


class NatsCharmEvents(CharmEvents):
    """NATS Custom Charm Events."""

    nats_started = EventSource(NatsStartedEvent)


SNAP_COMMON_PATH = Path("/var/snap/nats/common")
SERVER_PATH = SNAP_COMMON_PATH / "server"
SNAP_NAME = "nats"
NATS_SERVER_CONFIG_PATH = SERVER_PATH / "nats.cfg"
AUTH_TOKEN_PATH = SERVER_PATH / "auth_secret"
AUTH_TOKEN_LENGTH = 64
TLS_KEY_PATH = SERVER_PATH / "key.pem"
TLS_CERT_PATH = SERVER_PATH / "cert.pem"
TLS_CA_CERT_PATH = SERVER_PATH / "ca.pem"


class NatsCharm(CharmBase):
    """Charmed Operator to deploy NATS - a distributed message bus for services."""

    on: CharmEvents = NatsCharmEvents()
    state = StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self._snap = NATS()

        self.state.set_default(
            auth_token=NatsCharm.get_auth_token(AUTH_TOKEN_LENGTH),
        )

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.upgrade_charm, self._on_upgrade_charm)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

        listen_on_all_addresses = self.model.config["listen-on-all-addresses"]
        self.cluster = NatsCluster(self, "cluster", listen_on_all_addresses)
        self.framework.observe(self.on.cluster_relation_changed, self._on_config_changed)

        self.nats_client = NATSClientProvider(
            self, "client", listen_on_all_addresses, self.model.config["client-port"]
        )
        self.framework.observe(self.on.client_relation_joined, self._on_client_relation_joined)

        self.ca_client = CAClientRequires(self, "ca-client")
        self.framework.observe(self.ca_client.on.tls_config_ready, self._on_tls_config_ready)
        self.framework.observe(self.ca_client.on.ca_available, self._on_ca_available)

        self.nrpe_client = NRPEClient(self, "nrpe-external-master")
        self.framework.observe(self.nrpe_client.on.nrpe_available, self._on_nrpe_ready)

    def _on_client_relation_joined(self, event: RelationJoinedEvent):
        if self.ca_client.is_joined and not self.ca_client.is_ready:
            event.defer()
        self.nats_client.expose_nats(auth_token=self.state.auth_token)

    def _on_install(self, event: InstallEvent):
        try:
            core_res = self.model.resources.fetch("core")
        except ModelError:
            core_res = None
        try:
            nats_res = self.model.resources.fetch("nats")
        except ModelError:
            nats_res = None
        channel = self.model.config["snap-channel"]
        self._snap.install(channel=channel, core_res=core_res, nats_res=nats_res)

    def _on_upgrade_charm(self, event: UpgradeCharmEvent):
        self.ca_client.restore_state()

    def _on_config_changed(self, event: ConfigChangedEvent):
        config = dict(self.model.config)
        if not (config["tls-cert"] and config["tls-key"]) and self.ca_client.is_ready:
            logger.info("Configuring CA certificates from relation")
            key = self.ca_client.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
            cert = self.ca_client.certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode("utf-8")
            ca_cert = self.ca_client.ca_certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            ).decode("utf-8")
            # tls with CA's config
            config["tls-cert"] = cert
            config["tls-key"] = key
            config["tls-ca-cert"] = ca_cert

        self._reconfigure_nats(config)

    def _on_tls_config_ready(self, event: TlsConfigReady):
        if self.config["tls-key"] and self.config["tls-cert"]:
            logger.info(
                "Not reconfiguring NATS with CA as model configuration \
                        already has certificates"
            )
            return
        self._on_config_changed(event)

    def _on_ca_available(self, event):
        cn, sans = self._generate_cn_and_san()
        self.ca_client.request_server_certificate(cn, list(sans))

    def _on_nrpe_ready(self, event):
        if self.nrpe_client.is_available:
            check_name = "check_{}".format(self.model.unit.name.replace("/", "_"))
            self.nrpe_client.add_check(
                command=[
                    "/usr/lib/nagios/plugins/check_tcp",
                    "-H",
                    str(self.nats_client.listen_address),
                    "-p",
                    str(self.model.config["client-port"]),
                ],
                name=check_name,
            )
            self.nrpe_client.commit()

    def _generate_content_hash(self, content):
        m = hashlib.sha256()
        m.update(content.encode("utf-8"))
        return m.hexdigest()

    # FIXME: reduce this function's complexity to satisfy the linter
    def _reconfigure_nats(self, config):
        logger.info("Reconfiguring NATS")
        ctxt = {
            "client_port": config["client-port"],
            "cluster_port": config["cluster-port"],
            "cluster_listen_address": self.cluster.listen_address,
            "client_listen_address": self.nats_client.listen_address,
            "auth_token": self.state.auth_token,
            "peer_addresses": self.cluster.peer_addresses,
            "debug": config["debug"],
            "trace": config["trace"],
            "tls_cert": config["tls-cert"],
            "tls_key": config["tls-key"],
            "tls_ca_cert": config["tls-ca-cert"],
            "verify_tls_clients": config["verify-tls-clients"],
            "map_tls_clients": config["map-tls-clients"],
        }

        use_tls = NATS.setup_tls(
            tls_key=ctxt["tls_key"],
            tls_cert=ctxt["tls_cert"],
            ca_cert=ctxt["tls_ca_cert"],
        )

        changed = self._snap.configure(ctxt)
        if ctxt["tls_ca_cert"]:
            self.nats_client.set_tls_ca(ctxt["tls_ca_cert"])

        if changed or use_tls:
            self.nats_client.expose_nats(auth_token=self.state.auth_token)

        client_port = int(self.model.config["client-port"])
        self.unit.set_ports(client_port)
        logger.info(f"Opened port: {client_port} for access")

        if not self._snap.running:
            self.unit.status = BlockedStatus("failed to configure nats")
            return

        logger.info("NATS configuration complete")
        self.unit.status = ActiveStatus()

    def _generate_cn_and_san(self) -> tuple[str, set[str]]:
        # Use a reverse resolution for bind-address of a cluster endpoint as a heuristic to
        # determine a common name.
        common_name = socket.getnameinfo(
            (str(self.cluster.listen_address), 0), socket.NI_NAMEREQD
        )[0]
        san_addresses = set()
        san_addresses.add(str(self.cluster.listen_address))
        san_addresses.add(str(self.cluster.ingress_address))
        san_addresses.add(str(self.nats_client.listen_address))
        for addr in self.nats_client.ingress_addresses:
            san_addresses.add(str(addr))
        if self.model.config["listen-on-all-addresses"]:
            raise RuntimeError(
                "Generating certificates with listen-on-all-addresses option is not supported yet"
            )
            # TODO: update with all host interface addresses to implement this for listen-on-all-addresses.
        san_hostnames = set()
        for addr in san_addresses:
            # May raise gaierror.
            name = socket.getnameinfo((str(addr), 0), socket.NI_NAMEREQD)[0]
            san_hostnames.add(name)
        sans = san_addresses.union(san_hostnames)
        return common_name, sans

    @classmethod
    def get_auth_token(cls, length=None):
        """Generate a random auth token."""
        if not isinstance(length, int):
            raise RuntimeError("invalid length provided for a token")
        alphanumeric_chars = string.ascii_letters + string.digits
        rng = random.SystemRandom()
        return "".join([rng.choice(alphanumeric_chars) for _ in range(length)])

    def _on_start(self, _):
        self._snap.start()
        if self._snap.running:
            self.on.nats_started.emit()
        self.model.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(NatsCharm)
