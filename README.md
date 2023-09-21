# Charmed NATS Operator

## Description

This repository contains a [Juju Charm](https://charmhub.io/nats-charmers-nats)
for deploying [NATS](https://nats.io/) on virtual machines ([LXD](https://ubuntu.com/lxd)).
This charm provides a way to deploy a NATS core cluster.

Current features:

* installation of nats-server via a snap (either from the store or a resource);
* clustering with route URLs automatically added to the config of each unit;
* debug options.
* TLS support

### Clustering Notes

* NATS core does not have message persistence so leadership is not used for
  ordering of addition of units to the cluster - they come up as they are added
  and for a full mesh;
* Route URLs are added to all other peers on each unit so that there is no
  dependency on a particular unit for discovering others;
* Official NATS clients are multi-endpoint aware and will attempt to connect to
  a random NATS server and find the one that is alive so there is no need for a
  cluster virtual IP. Therefore, different NATS units can be in different
  subnets and are not tied to a shared L2 domain.

## Usage

### Basic Usage

To deploy a single unit of NATS using its default configuration

```shell
juju deploy <nats-charm-dir>
```

### Deploy multiple units for a cluster

To deploy a cluster with multiple members

```shell
juju deploy <nats-charm-dir> -n 3
```

### Enable Debug logs for NATS

```shell
juju config nats debug=true trace=true
juju ssh --unit nats/0
journalctl -f -u snap.nats.server.service
```

## Integrations (Relations)

Supported [relations](https://juju.is/docs/olm/relations):

#### `nats` interface:

The Charmed NATS Operator supports a `nats` interface to allow clients to connect
to the NATS cluster.

```yaml
provides:
      client:
          interface: nats
```

juju v2.x:

```shell
juju relate nats application
```

juju v3.x

```shell
juju integrate nats application
```

To remove a relation:

```shell
juju remove-relation nats application
```

#### `tls-certificates` interface:

The Charmed NATS Operator also supports TLS encryption on connections.

```yaml
requires:
    ca-client:
        interface: tls-certificates
```

To enable TLS:
```shell
# Deploy the TLS Certificates Operator.
# The Vault charm implements the same interface.
juju deploy cs:~containers/easyrsa

juju relate nats easyrsa
```

Note: The CA certificate obtained via a relation to the CA charm will also be exposed
for NATS charm clients.

#### `nats-cluster` interface:

The NATS charm has a peer relation to enable clustring for the NATS operator

```yaml
peers:
    cluster:
        interface: nats-cluster
```

#### `nrpe-external-master` interface:

This charm can integrate with the LMA stack and can expose metrics for observability
through this relation.

```yaml
provides:
  nrpe-external-master:
      interface: nrpe-external-master
      scope: container
```

## Security
Security issues in the NATS Operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File) on the [Anbox Cloud](https://bugs.launchpad.net/anbox-cloud) project. Please do not file GitHub issues about security issues.

## Contributing
Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/nats-operator/blob/main/CONTRIBUTING.md) for developer guidance.

## License
The Charmed NATS Operator is distributed under the Apache Software License, version 2.0. It installs/operates/depends on NATS, which is licensed under Apache Software License, version 2.0 as well.
