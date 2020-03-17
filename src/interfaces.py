import ipaddress

from ops.framework import Object


class NatsCluster(Object):

    def __init__(self, charm, relation_name, listen_on_all_addresses):
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        if listen_on_all_addresses:
            # This will create a listening socket for all IPv4 and IPv6 addresses.
            self._listen_address = ipaddress.ip_address('0.0.0.0')
        else:
            self._listen_address = None

    @property
    def is_joined(self):
        return self.framework.model.get_relation(self._relation_name) is not None

    @property
    def relation(self):
        return self.framework.model.get_relation(self._relation_name)

    @property
    def peer_addresses(self):
        addresses = []
        relation = self.relation
        if relation:
            for u in relation.units:
                addresses.append(relation.data[u]['ingress-address'])
        return addresses

    @property
    def listen_address(self):
        if self._listen_address is None:
            self._listen_address = self.model.get_binding(self._relation_name).network.bind_address
        return self._listen_address


class NatsClient(Object):

    def __init__(self, charm, relation_name, listen_on_all_addresses, client_port):
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        self._client_port = client_port
        self._listen_on_all_addresses = listen_on_all_addresses
        if listen_on_all_addresses:
            # This will create a listening socket for all IPv4 and IPv6 addresses.
            self._listen_address = ipaddress.ip_address('0.0.0.0')
        else:
            self._listen_address = None
        self._tls_ca = None

    @property
    def listen_address(self):
        if self._listen_address is None:
            addresses = set()
            for relation in self.model.relations[self._relation_name]:
                address = self.model.get_binding(relation).network.bind_address
                addresses.add(address)
            if len(addresses) > 1:
                raise Exception('Multiple potential listen addresses detected: NATS does not support that')
            elif addresses == 1:
                self._listen_address = addresses.pop()
            else:
                # Default to network information associated with an endpoint binding itself in absence of relations.
                self._listen_address = self.model.get_binding(self._relation_name).network.bind_address
        return self._listen_address

    def set_tls_ca(self, tls_ca):
        self._tls_ca = tls_ca

    def expose_nats(self):
        rel = self.model.get_relation(self._relation_name)
        if rel is not None:
            if self._tls_ca is not None:
                url = f'tls://{self.listen_address}:{self._client_port}'
            else:
                url = f'nats://{self.listen_address}:{self._client_port}'
            rel.data[self.model.unit]['url'] = url
            if self.model.unit.is_leader() and self._tls_ca is not None:
                rel.data[self.model.app]['ca_cert'] = self._tls_ca
