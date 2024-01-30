#!/usr/bin/env python3

import asyncio
import logging
import ssl

import nats
import ops

logger = logging.getLogger(__name__)


class ApplicationCharm(ops.CharmBase):
    """Application charm that connects to database charms."""

    def __init__(self, *args):
        super().__init__(*args)

        # Default charm events.
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.client_relation_changed, self._on_client_relation_changed)

    def _on_start(self, _):
        self.unit.status = ops.ActiveStatus()

    def _on_client_relation_changed(self, event):
        # FIXME: sometimes the remote unit i.e event.unit is empty when this
        # hook is fired so we try to pick the first unit from the relation data
        remote_unit = event.unit or event.relation.units.pop()
        unit_data = event.relation.data.get(remote_unit)
        if not unit_data:
            logger.error("data not found in relation")
            self.unit.status = ops.BlockedStatus("waiting for relation data")
            return
        url = unit_data.get("url")
        if not url:
            logger.error("url not found")
            self.unit.status = ops.BlockedStatus("waiting for relation data")
            return
        connect_opts = {}
        if url.startswith("tls"):
            cert = event.relation.data.get(event.app).get("ca_cert")
            if not cert:
                logger.error("ca_cert not found")
                self.unit.status = ops.BlockedStatus("waiting for relation data")
                return
            tls = ssl.create_default_context(cadata=cert)
            connect_opts.update({"tls": tls})

        # Since this charm individually relates to all the units, it verifies
        # the connection to each unit individually using their listen addresses
        # and check if each unit has the knowledge of cluster members as well.
        async def _verify_connection(url: str, opts: dict):
            if url.startswith("tls") and opts.get("tls"):
                raise Exception(
                    f"tls connection required for: {url}, but no ceritificate available"
                )
            client = await nats.connect(url, **opts)
            logger.info(f"connected to {url}")
            if self.config["check_clustering"]:
                logger.info("checking for clustering")
                assert len(client.servers) > 1, f"NATS not clustered: {client.servers}"
            channel_name = "test"
            message = b"testing"
            sub = await client.subscribe(channel_name)
            await client.publish(channel_name, message)
            msg = await sub.next_msg()
            assert (
                msg.data == message
            ), f"messages do not match. Expected: {message}, Got: {msg.data}"
            assert (
                msg.subject == channel_name
            ), f"messages do not match. Expected: {channel_name}, Got: {msg.subject}"
            logger.info("connection check complete")
            await sub.unsubscribe()

        loop = asyncio.get_event_loop()
        loop.run_until_complete(_verify_connection(url, connect_opts))
        self.unit.status = ops.ActiveStatus()


if __name__ == "__main__":
    ops.main(ApplicationCharm)
