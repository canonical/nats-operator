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
            self._listen_address = self.model.get_binding(self.relation).network.bind_address
        return self._listen_address


class NatsClient(Object):

    def __init__(self, charm, relation_name, listen_on_all_addresses):
        super().__init__(charm, relation_name)
        self._relation_name = relation_name
        if listen_on_all_addresses:
            # This will create a listening socket for all IPv4 and IPv6 addresses.
            self._listen_address = ipaddress.ip_address('0.0.0.0')
        else:
            self._listen_address = ipaddress.ip_address('127.0.0.1')

    @property
    def listen_address(self):
        if self._listen_address is None:
            addresses = []
            for relation in self.model.relations[self._relation_name]:
                address = self.model.get_binding(relation).network.bind_address
                if address not in addresses:
                    addresses.append(address)
            if len(addresses) > 1:
                raise Exception('Multiple potential listen addresses detected: NATS does not support that')
            elif len(addresses) == 0:
                self._listen_address = None
            else:
                self._listen_address = addresses[0]
        return self._listen_address
