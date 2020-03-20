# Overview

This charm provides a way to deploy a NATS core cluster. See https://nats.io/ for
more information about NATS itself.

Current features:

* installation of nats-server via a snap (either from the store or a resource);
* clustering with route URLs automatically added to the config of each unit;
* debug options.
* TLS support

# Clustering Notes

* NATS core does not have message persistence so leadership is not used for
  ordering of addition of units to the cluster - they come up as they are added
  and for a full mesh;
* Route URLs are added to all other peers on each unit so that there is no
  dependency on a particular unit for discovering others;
* Official NATS clients are multi-endpoint aware and will attempt to connect to
  a random NATS server and find the one that is alive so there is no need for a
  cluster virtual IP. Therefore, different NATS units can be in different
  subnets and are not tied to a shared L2 domain.

# Deploy

```bash
juju deploy <nats-charm-dir>
```

# Deploy with TLS Termination via a Relation

```bash
juju deploy <nats-charm-dir> -n 3
# The Vault charm implements the same interface.
juju deploy cs:~containers/easyrsa
juju relate nats easyrsa
```

A CA certificate obtained via a relation to a CA charm will also be exposed for NATS charm clients.

# Debug

```bash
juju config nats debug=true trace=true
juju ssh --unit nats/0
journalctl -f -u snap.nats.server.service
```
