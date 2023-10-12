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
from interfaces import CAClient, NatsClient, NatsCluster
from nats import NATS
from nrpe.client import NRPEClient  # noqa: E402
from ops import EventBase, EventSource, HookEvent, InstallEvent, StoredState, JujuVersion
from ops.charm import CharmBase, CharmEvents
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, ModelError, WaitingStatus

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

        self.state.set_default(
            auth_token=NatsCharm.get_auth_token(AUTH_TOKEN_LENGTH),
        )

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.upgrade_charm, self._reconfigure_nats)
        self.framework.observe(self.on.config_changed, self._reconfigure_nats)

        listen_on_all_addresses = self.model.config["listen-on-all-addresses"]
        self.cluster = NatsCluster(self, "cluster", listen_on_all_addresses)
        self.framework.observe(self.on.cluster_relation_changed, self._reconfigure_nats)

        self.client = NatsClient(
            self, "client", listen_on_all_addresses, self.model.config["client-port"]
        )
        self._snap = NATS()
        self.framework.observe(self.on.client_relation_joined, self._reconfigure_nats)

        self.ca_client = CAClient(self, "ca-client")
        self.framework.observe(self.ca_client.on.tls_config_ready, self._on_tls_config_ready)
        self.framework.observe(self.ca_client.on.ca_available, self._reconfigure_nats)

        self.nrpe_client = NRPEClient(self, "nrpe-external-master")
        self.framework.observe(self.nrpe_client.on.nrpe_available, self._reconfigure_nats)

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

    def _on_tls_config_ready(self, event):
        self._reconfigure_nats(event)

    def _generate_content_hash(self, content):
        m = hashlib.sha256()
        m.update(content.encode("utf-8"))
        return m.hexdigest()

    # FIXME: reduce this function's complexity to satisfy the linter
    def _reconfigure_nats(self, event: HookEvent):  # noqa: C901
        logger.info("Reconfiguring NATS")
        ctxt = {
            "client_port": self.model.config["client-port"],
            "cluster_port": self.model.config["cluster-port"],
            "cluster_listen_address": self.cluster.listen_address,
            "client_listen_address": self.client.listen_address,
            "auth_token": self.state.auth_token,
            "peer_addresses": self.cluster.peer_addresses,
            "debug": self.model.config["debug"],
            "trace": self.model.config["trace"],
        }

        cert = self.model.config["tls-cert"]
        key = self.model.config["tls-key"]
        ca_cert = self.model.config["tls-ca-cert"]

        if not (cert or key):
            if self.ca_client.is_joined:
                if not self.ca_client.is_ready:
                    cn, sans = self._generate_cn_and_san()
                    self.ca_client.request_server_certificate(cn, list(sans))
                    self.model.unit.status = WaitingStatus(
                        "Waiting for TLS configuration data from the CA client."
                    )
                    return
                else:
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
        ctxt.update(
            {
                "tls_key": key,
                "tls_cert": cert,
                "tls_ca_cert": ca_cert,
                "verify_tls_clients": self.model.config["verify-tls-clients"],
                "map_tls_clients": self.model.config["map-tls-clients"],
            }
        )

        if ca_cert:
            self.client._set_tls_ca(ca_cert)

        if self.nrpe_client.is_available:
            check_name = "check_{}".format(self.model.unit.name.replace("/", "_"))
            self.nrpe_client.add_check(
                command=[
                    "/usr/lib/nagios/plugins/check_tcp",
                    "-H",
                    str(self.client.listen_address),
                    "-p",
                    str(self.model.config["client-port"]),
                ],
                name=check_name,
            )
            self.nrpe_client.commit()

        self._snap.configure(ctxt)
        self.client.expose_nats(auth_token=self.state.auth_token)

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
        san_addresses.add(str(self.client.listen_address))
        for addr in self.client.ingress_addresses:
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
