from ops.framework import Object


class NatsCluster(Object):

    def __init__(self, charm, relation_name):
        super().__init__(charm, relation_name)
        self.relation_name = relation_name

    @property
    def is_joined(self):
        return self.framework.model.get_relation(self.relation_name) is not None

    @property
    def relation(self):
        return self.framework.model.get_relation(self.relation_name)

    @property
    def peer_addresses(self):
        addresses = []
        relation = self.relation
        if relation:
            for u in self.relation.units:
                addresses.append(self.relation.data[u]['ingress-address'])
        return addresses

    @property
    def bind_address(self):
        return self.model.get_binding(self.relation_name).network.bind_address


class NatsClient(Object):

    def __init__(self, charm, relation_name):
        super().__init__(charm, relation_name)
        self.relation_name = relation_name

    @property
    def bind_address(self):
        return self.model.get_binding(self.relation_name).network.bind_address
