"""NATS Cluster Endpoint handler."""
import ipaddress

from ops.framework import Object


class NatsCluster(Object):
    """Peer relation `nats-cluster` interface for the NATS charm."""

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
    def peer_addresses(self):
        """Property to get addresses of the units in the cluster."""
        addresses = []
        relation = self.framework.model.get_relation(self._relation_name)
        if relation:
            for u in relation.units:
                addresses.append(relation.data[u]["ingress-address"])
        return addresses

    @property
    def listen_address(self):
        """Property to get the listen address."""
        if not self._listen_address:
            self._listen_address = self.model.get_binding(self._relation_name).network.bind_address
        return self._listen_address

    @property
    def ingress_address(self):
        """Property to get the ingress address."""
        if not self._ingress_address:
            self._ingress_address = self.model.get_binding(
                self._relation_name
            ).network.ingress_address
        return self._ingress_address
