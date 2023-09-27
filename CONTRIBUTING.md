# Contributing

## Overview

This documents explains the processes and practices recommended for contributing enhancements to
this operator.

- Generally, before developing enhancements to this charm, you should consider [opening an issue
  ](https://github.com/canonical/nats-operator/issues) explaining your use case.
- Familiarising yourself with the [Charmed Operator Framework](https://juju.is/docs/sdk) library
  will help you a lot when working on new features or bug fixes.
- All enhancements require review before being merged. Code review typically examines
  - code quality
  - test coverage
  - user experience for Juju administrators of this charm.
- Please help us out in ensuring easy to review branches by rebasing your pull request branch onto
  the `master` branch. This also avoids merge commits and creates a linear Git commit history.

## Developing

You can create an environment for development with `tox`:

```shell
tox devenv -e integration-juju3
source venv/bin/activate
```

### Testing

```shell
tox run -e format              # update your code according to linting rules
tox run -e lint                # code style
tox run -e unit                # unit tests
tox run -e integration-juju2   # integration tests for juju 2.9
tox run -e integration-juju3   # integration tests for juju 3.2
tox                            # runs 'lint' and 'unit' environments
```

## Build charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

### Deploy

```bash
# Create a model
juju add-model dev

# Enable DEBUG logging
juju model-config logging-config="<root>=INFO;unit=DEBUG"

# Deploy the charm
juju deploy ./nats_ubuntu-22.04-amd64.charm
```

## Canonical Contributor Agreement

Canonical welcomes contributions to the NATS Operator. Please check out our
[contributor agreement](https://ubuntu.com/legal/contributors)if you're
interested in contributing to the solution.
