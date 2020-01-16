# Overview

This charm provides a way to deploy a NATS core cluster.

Current features:

* installation of nats-server via a snap (either from the store or a resource);
* clustering with route URLs automatically added to the config of each unit;
* debug options.

TLS support is currently WIP but a cluster with a single certificate and key for
all units is possible to configure via the relevant config options.

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
juju deploy --resource nats=<path-to-nats-snap-file> <nats-charm-dir>
```

# Debug

```bash
juju config nats debug=true trace=true
juju ssh --unit nats/0
journalctl -f -u snap.nats.server.service
```
