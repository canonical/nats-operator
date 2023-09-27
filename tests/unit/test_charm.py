from pathlib import Path
from subprocess import CalledProcessError
from unittest.mock import PropertyMock, patch

import pytest
from charm import NatsCharm
from OpenSSL import crypto
from ops import ActiveStatus, BlockedStatus
from ops.testing import Harness


@pytest.fixture
def harness(request):
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


def test_on_install_with_snapd_resource(harness: Harness):
    with patch("charm.subprocess.check_call") as mocked_cmd, patch(
        "charm.SERVER_PATH"
    ) as mocked_server_path:
        harness.add_resource("core", "core.snap")
        harness.charm.on.install.emit()
        assert mocked_cmd.call_count == 3
        mocked_server_path.mkdir.return_value = None
        mocked_server_path.mkdir.assert_called_once()


def test_on_install_with_nats_resource(harness: Harness):
    with patch("charm.subprocess.check_call") as mocked_cmd, patch(
        "charm.SERVER_PATH"
    ) as mocked_server_path:
        harness.add_resource("nats", "nats")
        harness.charm.on.install.emit()
        mocked_server_path.mkdir.return_value = None
        mocked_server_path.mkdir.assert_called_once()
        assert mocked_cmd.call_count == 2


def DISABLED_test_on_install_snap_failure(harness: Harness):  # noqa: N802
    with patch("charm.subprocess.check_call") as mocked_cmd:
        mocked_cmd.side_effect = CalledProcessError(1, "snap install failed")
        harness.charm.on.install.emit()
        assert harness.model.unit.status == BlockedStatus("")


def test_on_start_all_successfull(harness: Harness):
    with patch("charm.subprocess.check_call"):
        harness.charm.on.start.emit()
        assert harness.model.unit.status == ActiveStatus("")
        assert harness.charm.state.is_started


def DISABLED_test_block_if_only_one_tls_key_or_cert_given(  # noqa: N802
    harness: Harness, tls_config: tuple[bytes, bytes]
):
    with patch(
        "charm.NatsCluster.listen_address", new_callable=PropertyMock
    ) as cluster_listen_address, patch(
        "charm.NatsClient.listen_address", new_callable=PropertyMock
    ) as client_listen_address, patch(
        "charm.NatsCharm.NATS_SERVER_CONFIG_PATH"
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
    token = NatsCharm.get_auth_token(NatsCharm.AUTH_TOKEN_LENGTH)
    assert len(token) == 64


def test_listen_all_addresses_blocks_charm(harness: Harness):
    with harness.hooks_disabled():
        harness.update_config({"listen-on-all-addresses": True})
    with pytest.raises(RuntimeError):
        with patch("charm.NatsCluster.listen_address", new_callable=PropertyMock), patch(
            "charm.NatsCluster.ingress_address", new_callable=PropertyMock
        ), patch("charm.NatsClient.listen_address", new_callable=PropertyMock), patch(
            "charm.socket.getnameinfo"
        ) as mocked_hostname:
            mocked_hostname.return_value = ("my-nats.com", "1234")
            harness.add_relation("ca-client", "easyrsa")
            harness.charm.on.config_changed.emit()
            assert harness.charm.unit.status == BlockedStatus(
                "Generating certificates with listen-on-all-addresses option is not supported yet"
            )


def test_on_config_changed_rewrites_config(tmp_path, harness: Harness):
    config_path = tmp_path / "nats.cfg"
    with patch(
        "charm.NatsCluster.listen_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsCluster.ingress_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsCharm.NATS_SERVER_CONFIG_PATH", new=Path(config_path)
    ) as mock_config_path, patch(
        "charm.NatsCharm._open_port", return_value=None
    ), patch(
        "charm.NatsClient.listen_address", new_callable=PropertyMock, return_value="1.2.3.4"
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
    with patch(
        "charm.NatsCluster.listen_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsCluster.ingress_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsClient.listen_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsCharm.NATS_SERVER_CONFIG_PATH"
    ), patch(
        "charm.NatsCharm._open_port", return_value=None
    ), patch.object(
        harness.charm, "nrpe_client"
    ) as mock_client:
        mock_client.is_available = PropertyMock(return_value=True)
        harness.charm.on.config_changed.emit()
        assert mock_client.add_check.called
        assert mock_client.commit.called


def test_published_nats_client_data_to_relation(harness: Harness):
    with patch(
        "charm.NatsCluster.listen_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsCluster.ingress_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsClient.listen_address", new_callable=PropertyMock, return_value="1.2.3.4"
    ), patch(
        "charm.NatsCharm.NATS_SERVER_CONFIG_PATH"
    ), patch(
        "charm.NatsCharm._open_port", return_value=None
    ):
        with harness.hooks_disabled():
            rel = harness.add_relation("client", harness.charm.app.name)
        harness.charm.on.config_changed.emit()
        data = harness.get_relation_data(rel, harness.charm.unit)
        assert "url" in data
