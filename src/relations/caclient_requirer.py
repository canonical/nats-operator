#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#
"""CA Client Relation Requirer."""

import json
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from ops import Application, EventBase, EventSource, Object, ObjectEvents, StoredState

logger = logging.getLogger(__name__)


class CAAvailable(EventBase):
    """Event for knowing if the CA is available."""

    pass


class TlsConfigReady(EventBase):
    """Event for configuring if the `tls-certificates` relation is ready."""

    pass


class CAClientEvents(ObjectEvents):
    """Event emitter for the NATS charm."""

    ca_available = EventSource(CAAvailable)
    tls_config_ready = EventSource(TlsConfigReady)


class CAClientRequires(Object):
    """Implement for the requires side in `tls-ceritificates` relation."""

    on: ObjectEvents = CAClientEvents()
    state = StoredState()

    def __init__(self, charm, relation_name):
        """Initialise relation for `tls-certificates`.

        Charm -- a NatsCharm instance.
        relation_name -- a name of the relation with the tls-certificates interface for this charm.
        common_name -- a name to place into the CN field of a certificate.
        sans -- Subject Alternative Names (per RFC 5280): names or IPs to include in a requested certificate.
        """
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        self._common_name = None
        self._sans = None
        self._charm = charm

        self.state.set_default(ca_certificate=None, key=None, certificate=None)

        self.framework.observe(charm.on[relation_name].relation_joined, self._on_relation_joined)
        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)

    @property
    def is_joined(self):
        """Property to know if the relation has been joined."""
        return self.framework.model.get_relation(self._relation_name) is not None

    @property
    def is_ready(self):
        """Property to know if the relation is ready."""
        return all(
            p is not None
            for p in (self.state.certificate, self.state.key, self.state.ca_certificate)
        )

    @property
    def certificate(self):
        """Property to get the configured certificate."""
        if self.state.certificate:
            return load_pem_x509_certificate(
                self.state.certificate.encode("utf-8"), backend=default_backend()
            )

    @property
    def key(self):
        """Property to get the configured private key."""
        if self.state.key:
            return load_pem_private_key(
                self.state.key.encode("utf-8"), password=None, backend=default_backend()
            )

    @property
    def ca_certificate(self):
        """Property to get the configured CA certificate."""
        if self.state.ca_certificate:
            return load_pem_x509_certificate(
                self.state.ca_certificate.encode("utf-8"), backend=default_backend()
            )

    def _on_relation_joined(self, event):
        self.on.ca_available.emit()

    def request_server_certificate(self, common_name, sans):
        """Request a new server certificate.

        If arguments do not change from a previous request, then a new certificate will not
        be requested. This method can be useful if a list of SANS has changed during the
        lifetime of a charm.

        common_name -- a new common name to use.
        sans -- an updated list of Subject Alternative Names to use.
        """
        rel = self.framework.model.get_relation(self._relation_name)
        logger.info(f"Requesting a CA certificate. Common name: {common_name}, SANS: {sans}")
        rel_data = rel.data[self.model.unit]
        rel_data["common_name"] = common_name
        rel_data["sans"] = json.dumps(sans)

    def _get_certs(self, data: dict):
        cert = data.get(f'{self.model.unit.name.replace("/", "_")}.server.cert')
        key = data.get(f'{self.model.unit.name.replace("/", "_")}.server.key')
        ca = data.get("ca")
        return ca, key, cert

    def _on_relation_changed(self, event):
        # easy-rsa is not HA so there is only one unit to work with and Vault uses one leader unit to
        # write responses and does not (at the time of writing) rely on app relation data.
        remote_data = event.relation.data[event.unit]
        self.state.ca_certificate, self.state.key, self.state.certificate = self._get_certs(
            remote_data
        )

        if not (self.ca_certificate and self.key and self.certificate):
            logger.info(
                "A CA has not yet exposed a requested certificate, key and CA certificate."
            )
            return
        self.on.tls_config_ready.emit()

    def restore_state(self):
        """Restore certificate state from relation data after a restart."""
        relation = self.model.get_relation(self._relation_name)
        remote_unit = None
        for member in relation.data.keys():
            if not isinstance(member, Application) and member != self._charm.unit:
                remote_unit = member
                break
        self.framework.breakpoint()
        if remote_unit:
            remote_data = relation.data[remote_unit]
            self.state.ca_certificate, self.state.key, self.state.certificate = self._get_certs(
                remote_data
            )
            logger.info("Restored certificate state")
