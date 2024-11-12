#
# Copyright 2024 Canonical Ltd.  All rights reserved.
#
from pathlib import Path
from subprocess import CalledProcessError
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from OpenSSL import crypto
from ops import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import NatsCharm


@pytest.fixture
def harness(request):
    with patch("nats_config.snap.SnapCache"):
        harness = Harness(NatsCharm)
        request.addfinalizer(harness.cleanup)
        harness.begin()
        yield harness


@pytest.fixture
def tls_config() -> tuple[bytes, bytes]:
    # create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().O = "Canonical"
    cert.get_subject().OU = "Anbox Cloud"
    cert.get_subject().CN = "anbox-cloud.io"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha1")
    return crypto.dump_privatekey(crypto.FILETYPE_PEM, key), crypto.dump_certificate(
        crypto.FILETYPE_PEM, cert
    )


def test_on_install_with_snapd_resource(request):
    with patch("nats_config.NATS.SERVER_PATH") as mocked_server_path, patch(
        "nats_config.snap"
    ) as mocked_snap:
        harness = Harness(NatsCharm)
        mocked_snap.install_local = MagicMock()
        request.addfinalizer(harness.cleanup)
        harness.begin()
        harness.add_resource("core", "core.snap")
        harness.charm.on.install.emit()
        mocked_server_path.mkdir.return_value = None
        mocked_server_path.mkdir.assert_called_once()
        mocked_snap.install_local.assert_called_once()


def test_on_install_with_nats_resource(request):
    with patch("nats_config.snap") as mocked_snap, patch(
        "nats_config.NATS.SERVER_PATH"
    ) as mocked_server_path:
        harness = Harness(NatsCharm)
        mocked_snap.install_local = MagicMock()
        request.addfinalizer(harness.cleanup)
        harness.begin()
        harness.add_resource("nats", "nats.snap")
        harness.charm.on.install.emit()
        mocked_server_path.mkdir.return_value = None
        mocked_server_path.mkdir.assert_called_once()
        mocked_snap.install_local.assert_called_once()


def DISABLED_test_on_install_snap_failure(harness: Harness):  # noqa: N802
    with patch("charm.subprocess.check_call") as mocked_cmd:
        mocked_cmd.side_effect = CalledProcessError(1, "snap install failed")
        harness.charm.on.install.emit()
        assert harness.model.unit.status == BlockedStatus("")


def test_on_start_all_successfull(harness: Harness):
    harness.charm.on.start.emit()
    assert harness.model.unit.status == ActiveStatus("")


def DISABLED_test_block_if_only_one_tls_key_or_cert_given(  # noqa: N802
    harness: Harness, tls_config: tuple[bytes, bytes]
):
    with patch(
        "charm.NatsCluster.listen_address", new_callable=PropertyMock
    ) as cluster_listen_address, patch(
        "charm.NATSClientProvider.listen_address", new_callable=PropertyMock
    ) as client_listen_address, patch(
        "charm.NATS_SERVER_CONFIG_PATH"
    ) as mock_config_path, patch(
        "charm.NatsCharm._open_port"
    ):
        client_listen_address.return_value = "1.2.3.4"
        cluster_listen_address.return_value = "4.3.2.1"
        mock_config_path.write_text.return_value = None
        harness.update_config({"tls-key": tls_config[0].decode("ascii")})
        assert harness.charm.unit.status == BlockedStatus(
            "both TLS key and TLS cert must be specified"
        )


def test_generate_auth_token():
    token = NatsCharm.get_auth_token(64)
    assert len(token) == 64


def test_listen_all_addresses_blocks_charm(harness: Harness):
    with harness.hooks_disabled():
        harness.update_config({"listen-on-all-addresses": True})
    with pytest.raises(RuntimeError):
        with patch("charm.NatsCluster.listen_address", new_callable=PropertyMock), patch(
            "charm.NatsCluster.ingress_address", new_callable=PropertyMock
        ), patch("charm.NATSClientProvider.listen_address", new_callable=PropertyMock), patch(
            "charm.socket.getnameinfo"
        ) as mocked_hostname:
            mocked_hostname.return_value = ("my-nats_config.com", "1234")
            harness.add_relation("ca-client", "easyrsa")
            harness.charm.ca_client.on.ca_available.emit()
            assert harness.charm.unit.status == BlockedStatus(
                "Generating certificates with listen-on-all-addresses option is not supported yet"
            )


def test_on_config_changed_rewrites_config(tmp_path, harness: Harness):
    config_path = tmp_path / "nats_config.cfg"
    with patch(
        "charm.NatsCluster.listen_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsCluster.ingress_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "nats_config.NATS.CONFIG_PATH", new=Path(config_path)
    ) as mock_config_path, patch(
        "charm.NATSClientProvider.listen_address",
        new_callable=PropertyMock,
        return_value="1.2.3.4",
    ):
        harness.update_config(
            {
                "client-port": 1234,
                "cluster-port": 2134,
                "debug": False,
                "trace": False,
            }
        )
        assert harness.charm.unit.status == ActiveStatus("")
        before = mock_config_path.read_text()
        harness.update_config(
            {
                "debug": True,
                "trace": True,
            }
        )
        after = mock_config_path.read_text()
        assert before != after


def test_writes_nrpe_checks_on_nrpe_available(harness: Harness):
    mocked_check = MagicMock(return_value=None)
    mocked_commit = MagicMock(return_value=None)
    with patch.multiple(
        harness.charm.nrpe_client,
        add_check=mocked_check,
        commit=mocked_commit,
        state=MagicMock(nrpe_ready=True),
    ), patch.object(harness.charm, "nats_client", MagicMock()):
        harness.charm.nrpe_client.on.nrpe_available.emit()

        assert mocked_check.called, mocked_check.mock_calls
        assert mocked_commit.called, mocked_check.mock_calls


def test_published_nats_client_data_to_relation(harness: Harness):
    with patch(
        "charm.NatsCluster.listen_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsCluster.ingress_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NATSClientProvider.listen_address",
        new_callable=PropertyMock,
        return_value="1.2.3.4",
    ), patch(
        "nats_config.NATS.CONFIG_PATH"
    ):
        with harness.hooks_disabled():
            rel = harness.add_relation("client", harness.charm.app.name)
        harness.charm.on.config_changed.emit()
        data = harness.get_relation_data(rel, harness.charm.unit)
        assert "url" in data
