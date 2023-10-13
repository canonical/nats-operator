# See LICENSE file for licensing details.

"""Control NATS on a host system. Provides a NATS class."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path

from charms.operator_libs_linux.v2 import snap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

SNAP_NAME = "nats"


@dataclass
class NATSConfig:
    """Class representing configuration data for NATS."""

    client_port: int = -1
    cluster_port: int = -1
    cluster_listen_address: str = ""
    client_listen_address: str = ""
    peer_addresses: list[str] = field(default_factory=list)
    debug: bool = False
    trace: bool = False
    use_tls: bool = False
    tls_key_path: Path | None = None
    tls_cert_path: Path | None = None
    tls_ca_cert_path: Path | None = None
    verify_tls_clients: bool = False
    map_tls_clients: bool = False
    auth_token: str = field(default="", repr=False)


class NATS:
    """Class representing NATS on a host system."""

    AUTH_TOKEN_LENGTH = 64
    SNAP_NAME = "nats"

    SNAP_COMMON_PATH = Path("/var/snap/nats/common")
    SERVER_PATH = SNAP_COMMON_PATH / "server"

    CONFIG_PATH = SERVER_PATH / "nats.cfg"
    AUTH_TOKEN_PATH = SERVER_PATH / "auth_secret"
    TLS_KEY_PATH = SERVER_PATH / "key.pem"
    TLS_CERT_PATH = SERVER_PATH / "cert.pem"
    TLS_CA_CERT_PATH = SERVER_PATH / "ca.pem"

    def __init__(self, *args):
        super().__init__(*args)
        self._current_config = self._current_config_hash()

    def _generate_content_hash(self, content: str):
        m = hashlib.sha256()
        m.update(content.encode("utf-8"))
        return m.hexdigest()

    def _current_config_hash(self) -> str:
        config = None
        try:
            with open(self.CONFIG_PATH, "rb") as f:
                config = f.read()
        except FileNotFoundError:
            logger.debug("Current configuration not found, no previous hash generated")
            return ""
        return self._generate_content_hash(config.decode("utf-8"))

    def install(
        self,
        channel: str | None = None,
        core_res: Path | None = None,
        nats_res: Path | None = None,
    ):
        """Install the NATS snap package."""
        # Install the snaps from a resource if provided. Alternatively, snapd
        # will attempt to download it automatically.
        if core_res and core_res.stat().st_size:
            snap.install_local(core_res, dangerous=True)

        if nats_res and nats_res.stat().st_size:
            snp = snap.install_local(nats_res, dangerous=True)
        else:
            snp = self._snap

        if not snp.present:
            snp.ensure(snap.SnapState.Latest, channel=channel)
        snp.stop(disable=True)

        self.SERVER_PATH.mkdir(exist_ok=True, mode=0o0700)

        try:
            self._snap.ensure(snap.SnapState.Latest, channel=channel)
        except snap.SnapError as e:
            logger.error("could not install nats. Reason: %s", e.message)
            logger.debug(e, exc_info=True)
            raise e

    def refresh(self, channel: str):
        """Refresh the NATS snap if there is a new revision."""
        # The operation here is exactly the same, so just call the install method
        self.install(channel)

    def start(self):
        """Start and enable NATS using the snap service."""
        self._snap.start(enable=True)

    def restart(self):
        """Start and enable NATS using the snap service."""
        self._snap.restart()

    def stop(self):
        """Stop NATS using the snap service."""
        self._snap.stop(disable=True)

    def remove(self):
        """Remove the NATS snap, preserving config and data."""
        self._snap.ensure(snap.SnapState.Absent)

    def _setup_tls(self, tls_cert: str, tls_key: str, ca_cert: str | None = None) -> bool:
        """Handle TLS parameters passed via charm config.

        Values are loaded and parsed to provide basic validation and then used to
        determine whether to use TLS in a charm by or not. If TLS is to be used,
        the TLS config content is written to the necessary files.
        """
        only_one_is_set = bool(tls_cert) ^ bool(tls_key)
        if only_one_is_set:
            raise Exception("both TLS key and TLS cert must be specified")
        use_tls = all([bool(tls_cert), bool(tls_key)])

        if not use_tls:
            return False

        if tls_key:
            load_pem_private_key(tls_key.encode("utf-8"), password=None, backend=default_backend())
        if tls_cert:
            load_pem_x509_certificate(tls_cert.encode("utf-8"), backend=default_backend())
        if ca_cert:
            load_pem_x509_certificate(ca_cert.encode("utf-8"), backend=default_backend())

        self.TLS_KEY_PATH.write_text(tls_key)
        self.TLS_CERT_PATH.write_text(tls_cert)
        # A CA cert is optional because NATS may rely on system-trusted (core snap) CA certs.
        if ca_cert:
            self.TLS_CA_CERT_PATH.write_text(ca_cert)
            logger.debug("Created ca cert for nats")
        return True

    def configure(self, config: dict, restart: bool = True) -> bool:
        """Configure NATS on the host system. Restart NATS by default."""
        config_changed = False
        use_tls = self._setup_tls(
            tls_key=config["tls_key"],
            tls_cert=config["tls_cert"],
            ca_cert=config.get("tls_ca_cert"),
        )

        cfg = NATSConfig(
            use_tls=use_tls,
            tls_cert_path=self.TLS_CERT_PATH,
            tls_key_path=self.TLS_KEY_PATH,
            tls_ca_cert_path=self.TLS_CA_CERT_PATH,
            map_tls_clients=config.get("map_tls_clients", False),
            verify_tls_clients=config.get("verify_tls_clients", False),
            auth_token=config["auth_token"],
            debug=config["debug"],
            trace=config["trace"],
            client_listen_address=config["client_listen_address"],
            client_port=config["client_port"],
            cluster_listen_address=config["cluster_listen_address"],
            cluster_port=config["cluster_port"],
            peer_addresses=config["peer_addresses"],
        )
        new_config = self._generate_config(cfg)
        config_hash = self._generate_content_hash(new_config)

        if self._current_config != config_hash:
            logger.info(f"Config has changed - re-rendering a template to {self.CONFIG_PATH}")
            self.CONFIG_PATH.write_text(new_config)
            self._current_config = config_hash
            config_changed = True

            # Restart the snap service only if it was running already
            if restart:
                self._snap.restart()
        return config_changed or use_tls

    def _generate_config(self, config: NATSConfig) -> str:
        tenv = Environment(loader=FileSystemLoader("templates"))
        template = tenv.get_template("nats.cfg.j2")
        return template.render(asdict(config))

    @property
    def installed(self):
        """Report if the NATS snap is installed."""
        return self._snap.present

    @property
    def running(self):
        """Report if the 'server' snap service is running."""
        return self._snap.services["server"]["active"]

    @property
    def version(self) -> str:
        """Report the version of NATS currently installed."""
        if self.installed:
            snaps = self._snap._snap_client.get_installed_snaps()
            for installed_snap in snaps:
                if installed_snap["name"] == self._snap.name:
                    return installed_snap["version"]

        raise snap.SnapError(f"{SNAP_NAME} snap not installed, cannot fetch version")

    @property
    def _snap(self):
        """Return a representation of the NATS snap."""
        cache = snap.SnapCache()
        return cache[SNAP_NAME]
