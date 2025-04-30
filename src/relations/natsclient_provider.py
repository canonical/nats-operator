#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#
"""NATS Client Provider for `nats` interface."""

import ipaddress
import logging

from ops import JujuVersion, Object, Secret, SecretNotFoundError, StoredState

logger = logging.getLogger(__name__)

NATS_URL_SECRET_LABEL_PREFIX = "nats-protected-url"


class NATSClientProvider(Object):
    """`nats` interface for the client to NATS."""

    state = StoredState()

    def __init__(self, charm, relation_name, listen_on_all_addresses, client_port):
        super().__init__(charm, relation_name)
        self._charm = charm
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

    def set_tls_ca(self, tls_ca):
        """Set CA to publish this certificate to the remote unit via the Client relation."""
        self.state.tls_ca = tls_ca

    def _ensure_secret(self, url: str, label: str) -> Secret:
        """Retrieve an existing secret or create a new one if it does not exist."""
        try:
            secret = self.model.get_secret(label=label)
        except SecretNotFoundError:
            secret = self.model.unit.add_secret(
                content={"url": url},
                label=label,
                description="Protected NATS connection URL for clients to access the messaging service",
            )
        return secret

    def expose_nats(self, auth_token=None):
        """Exposes NATS to the outside world by publishing cert and url to relation data."""
        tls_ca_available = self.state.tls_ca is not None
        protocol = "tls" if tls_ca_available else "nats"
        token_field = f"{auth_token}@" if auth_token else ""
        url = f"{protocol}://{token_field}{self.listen_address}:{self._client_port}"

        relations = self.model.relations[self._relation_name]
        for rel in relations:
            rel.data[self.model.unit]["url"] = url
            if self.model.unit.is_leader() and tls_ca_available:
                rel.data[self.model.app]["ca_cert"] = self.state.tls_ca

            # Use secrets only if juju > 3.0
            # TODO: make this the only way to share url once all charms use the
            # charm-lib and juju > 3.0
            if JujuVersion.from_environ().has_secrets:
                # Always create a secet with old secret label to maintain backward compatibility.
                label = NATS_URL_SECRET_LABEL_PREFIX
                new_secret_label = f"{NATS_URL_SECRET_LABEL_PREFIX}_{self._charm.unit.name}"
                for secret_label in [label, new_secret_label]:
                    self._ensure_secret(url, secret_label).grant(rel)

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
