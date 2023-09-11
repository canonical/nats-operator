"""List of defined interfaces."""
import ipaddress
import json
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from ops.framework import EventBase, EventSource, Object, ObjectEvents, StoredState

logger = logging.getLogger(__name__)


class NatsCluster(Object):
    """Peer relation `nat-cluster` interface for the NATS charm."""

    def __init__(self, charm, relation_name, listen_on_all_addresses):
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        if listen_on_all_addresses:
            # This will create a listening socket for all IPv4 and IPv6 addresses.
            self._listen_address = ipaddress.ip_address("0.0.0.0")
            self._ingress_address = ipaddress.ip_address("0.0.0.0")
        else:
            self._listen_address = None
            self._ingress_address = None

    @property
    def is_joined(self):
        """Property to know if the relation has been joined."""
        return self.framework.model.get_relation(self._relation_name) is not None

    @property
    def relation(self):
        """Property to get the name of the relation."""
        return self.framework.model.get_relation(self._relation_name)

    @property
    def peer_addresses(self):
        """Property to get addresses of the units in the cluster."""
        addresses = []
        relation = self.relation
        if relation:
            for u in relation.units:
                addresses.append(relation.data[u]["ingress-address"])
        return addresses

    @property
    def listen_address(self):
        """Property to get the listen address."""
        if self._listen_address is None:
            self._listen_address = self.model.get_binding(self._relation_name).network.bind_address
        return self._listen_address

    @property
    def ingress_address(self):
        """Property to get the ingress address."""
        if self._ingress_address is None:
            self._ingress_address = self.model.get_binding(
                self._relation_name
            ).network.ingress_address
        return self._ingress_address


class NatsClient(Object):
    """`nats` interface for the client to NATS."""

    state = StoredState()

    def __init__(self, charm, relation_name, listen_on_all_addresses, client_port):
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        self._client_port = client_port
        self._listen_on_all_addresses = listen_on_all_addresses
        if listen_on_all_addresses:
            # This will create a listening socket for all IPv4 and IPv6 addresses.
            self._listen_address = ipaddress.ip_address("0.0.0.0")
        else:
            self._listen_address = None
        self._ingress_addresses = None
        self.state.set_default(tls_ca=None)

    @property
    def listen_address(self):
        """Property to get the listen address."""
        if self._listen_address is None:
            addresses = set()
            for relation in self.model.relations[self._relation_name]:
                address = self.model.get_binding(relation).network.bind_address
                addresses.add(address)
            if len(addresses) > 1:
                raise Exception(
                    "Multiple potential listen addresses detected: NATS does not support that"
                )
            elif addresses == 1:
                self._listen_address = addresses.pop()
            else:
                # Default to network information associated with an endpoint binding itself in absence of relations.
                self._listen_address = self.model.get_binding(
                    self._relation_name
                ).network.bind_address
        return self._listen_address

    def _set_tls_ca(self, tls_ca):
        self.state.tls_ca = tls_ca

    def expose_nats(self, auth_token=None):
        """Exposes NATS to the outside world."""
        relations = self.model.relations[self._relation_name]
        for rel in relations:
            token_field = ""
            if auth_token is not None:
                token_field = f"{auth_token}@"
            if self.state.tls_ca is not None:
                url = f"tls://{token_field}{self.listen_address}:{self._client_port}"
            else:
                url = f"nats://{token_field}{self.listen_address}:{self._client_port}"
            rel.data[self.model.unit]["url"] = url
            if self.model.unit.is_leader() and self.state.tls_ca is not None:
                rel.data[self.model.app]["ca_cert"] = self.state.tls_ca

    @property
    def ingress_addresses(self):
        """Property to get the ingress address."""
        # Even though NATS does not support multiple listening addresses that does not mean there
        # cannot be multiple ingress addresses clients would use.
        if self._ingress_addresses is None:
            self._ingress_addresses = set()
            for relation in self.model.relations[self._relation_name]:
                self._ingress_addresses.add(
                    self.model.get_binding(relation).network.ingress_address
                )
        return self._ingress_addresses


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


class CAClient(Object):
    """Interface for the `tls-ceritificates` relation."""

    on: ObjectEvents = CAClientEvents()
    state = StoredState()

    def __init__(self, charm, relation_name):
        """Charm -- a NatsCharm instance.

        relation_name -- a name of the relation with the tls-certificates interface for this charm.
        common_name -- a name to place into the CN field of a certificate.
        sans -- Subject Alternative Names (per RFC 5280): names or IPs to include in a requested certificate.
        """
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        self._common_name = None
        self._sans = None

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
        return load_pem_x509_certificate(
            self.state.certificate.encode("utf-8"), backend=default_backend()
        )

    @property
    def key(self):
        """Property to get the configured private key."""
        return load_pem_private_key(
            self.state.key.encode("utf-8"), password=None, backend=default_backend()
        )

    @property
    def ca_certificate(self):
        """Property to get the configured CA certificate."""
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

    def _on_relation_changed(self, event):
        # easy-rsa is not HA so there is only one unit to work with and Vault uses one leader unit to
        # write responses and does not (at the time of writing) rely on app relation data.
        remote_data = event.relation.data[event.unit]

        cert = remote_data.get(f'{self.model.unit.name.replace("/", "_")}.server.cert')
        key = remote_data.get(f'{self.model.unit.name.replace("/", "_")}.server.key')
        ca = remote_data.get("ca")
        if cert is None or key is None or ca is None:
            logger.info(
                "A CA has not yet exposed a requested certificate, key and CA certificate."
            )
            return
        self.state.certificate = cert
        self.state.key = key
        self.state.ca_certificate = ca
        self.on.tls_config_ready.emit()
