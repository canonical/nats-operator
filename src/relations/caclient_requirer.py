#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#
"""CA Client Relation Requirer."""

import ipaddress
import json
import logging
from itertools import filterfalse
from typing import Optional

import ops
from charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateAvailableEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from ops import (
    Application,
    EventBase,
    EventSource,
    Object,
    ObjectEvents,
    SecretChangedEvent,
    StoredState,
)
from ops.model import SecretNotFoundError

PRIVATE_KEY_SECRET_LABEL_PREFIX = "private-key_"

logger = logging.getLogger(__name__)


def is_ip_address(value: str) -> bool:
    """Return True if the input value is a valid IPv4 address; False otherwise."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


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
        """
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        self._charm = charm
        self._has_secret_support = ops.JujuVersion.from_environ().has_secrets
        unit_name = self._charm.model.unit.name.replace("/", "_")
        self._private_key_secret_label = f"{PRIVATE_KEY_SECRET_LABEL_PREFIX}{unit_name}"

        self.framework.observe(charm.on.secret_changed, self._on_secret_changed)

        self.state.set_default(ca_certificate=None, key=None, certificate=None)

        self.framework.observe(charm.on[relation_name].relation_joined, self._on_relation_joined)
        self.framework.observe(charm.on[relation_name].relation_changed, self._on_relation_changed)

        # Handle the certificates send by the TLS charm which makes use of the tls certificates
        # library which sends the csr request via `certificate_signing_requests` in the data bag.
        # The above certificates_relation_join and certificates_relation_changed events remain for
        # the TLS charm which sends the request via `common_name` and `sans`. E.g. easy-rsa
        self.certs = TLSCertificatesRequiresV2(self._charm, relation_name)
        self.framework.observe(self.certs.on.certificate_available, self._on_certificate_available)

    @property
    def is_joined(self):
        """Property to know if the relation has been joined."""
        return self.framework.model.get_relation(self._relation_name) is not None

    @property
    def is_ready(self):
        """Property to know if the relation is ready."""
        return all(p is not None for p in (self.certificate, self.key, self.ca_certificate))

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
        private_key = self._get_private_key()
        if private_key:
            return load_pem_private_key(
                private_key.encode("utf-8"), password=None, backend=default_backend()
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
        logger.info(f"Requesting a CA certificate. Common name: {common_name}, SANS: {sans}")
        private_key = self._generate_private_key()
        sans_ip = list(filter(is_ip_address, sans))
        sans_dns = list(filterfalse(is_ip_address, sans))
        csr = generate_csr(
            private_key=private_key,
            subject=common_name,
            sans_ip=sans_ip,
            sans_dns=sans_dns,
        )
        self.certs.request_certificate_creation(certificate_signing_request=csr)

        # Pass the common_name and sans via unit data as for the easy-rsa charm,
        # calling certs.request_certificate_creation would only return a client
        # certificate instead of a server certificate.
        rel = self.framework.model.get_relation(self._relation_name)
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
        remote_data = event.relation.data.get(event.unit)
        if not remote_data:
            return

        ca_certificate, key, certificate = self._get_certs(remote_data)
        if not (ca_certificate and key and certificate):
            logger.info(
                "A CA has not yet exposed a requested certificate, key and CA certificate."
            )
            return

        if (
            ca_certificate != self.state.ca_certificate
            or certificate != self.state.certificate
            or key != self._get_private_key()
        ):
            self.state.ca_certificate = ca_certificate
            self.state.certificate = certificate
            if self._save_private_key(key):
                self.on.tls_config_ready.emit()

    def restore_state(self):
        """Restore certificate state from relation data after a restart."""
        relation = self.model.get_relation(self._relation_name)
        if not relation:
            return

        remote_unit = None
        for member in relation.data.keys():
            if not isinstance(member, Application) and member != self._charm.unit:
                remote_unit = member
                break
        self.framework.breakpoint()
        if remote_unit:
            remote_data = relation.data[remote_unit]
            ca_certificate, key, certificate = self._get_certs(remote_data)

            if ca_certificate and key and certificate:
                self.state.ca_certificate = ca_certificate
                self.state.certificate = certificate
                self._save_private_key(key)

            logger.info("Restored certificate state")

    def _get_private_key(self) -> Optional[str]:
        if not self._has_secret_support:
            return self.state.key
        else:
            try:
                secret = self.model.get_secret(label=self._private_key_secret_label)
                private_key = secret.get_content(refresh=True).get("private-key")
                if private_key:
                    return private_key
            except SecretNotFoundError:
                pass
            return None

    def _generate_private_key(self) -> bytes:
        private_key = self._get_private_key()
        if private_key:
            return private_key.encode("utf-8")

        private_key = generate_private_key(key_size=4096)
        self._save_private_key(private_key.decode("utf-8"))
        return private_key

    def _save_private_key(self, private_key: str):
        if self._has_secret_support:
            try:
                secret = self.model.get_secret(label=self._private_key_secret_label)
                current_content = secret.get_content(refresh=True)
                if current_content.get("private-key") != private_key:
                    secret.set_content({"private-key": private_key})
                    # Rely on the secret_changed function to emit the tls_config_ready
                    # event once a new revision is successfully added.
                    return False
            except SecretNotFoundError:
                self._charm.unit.add_secret(
                    content={"private-key": private_key},
                    label=self._private_key_secret_label,
                    description="Private key used for certificate generation",
                )
        else:
            self.state.key = private_key
        return True

    def _on_secret_changed(self, event: SecretChangedEvent):
        if event.secret.label == self._private_key_secret_label and self.is_ready:
            self.on.tls_config_ready.emit()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handle the event when a TLS certificate becomes available.

        This method is used by TLS charms that utilize the tls certificates library
        and request certificates via the `certificate_signing_requests` data bag.
        E.g. self-signed-certificates charm
        """
        if event.certificate and event.ca:
            self.state.certificate = event.certificate
            self.state.ca_certificate = event.ca
            self.on.tls_config_ready.emit()
