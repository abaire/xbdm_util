"""See https://sourceware.org/gdb/onlinedocs/gdb/Remote-Protocol.html"""
from __future__ import annotations

import logging
import socket
from typing import Callable
from typing import List
from typing import Optional
from typing import Tuple

from xbdm import ip_transport
from xbdm import xbdm_transport

logger = logging.getLogger(__name__)


class GDBTransport(ip_transport.IPTransport):
    """GDB Stub translation of XDBM functions."""

    def __init__(self, xbdm: xbdm_transport.XBDMTransport):
        super().__init__(process_callback=self._on_bytes_read)
        self._xbdm = xbdm

    def _on_bytes_read(self, _ignored):
        pass


def _handle_build_command(
    _args: List[str],
) -> Optional[
    Callable[
        [xbdm_transport.XBDMTransport, socket.socket, Tuple[str, int]],
        Optional[ip_transport.IPTransport],
    ]
]:
    def construct_transport(
        xbdm: xbdm_transport.XBDMTransport,
        remote: socket.socket,
        remote_addr: Tuple[str, int],
    ) -> Optional[ip_transport.IPTransport]:
        ret = GDBTransport(xbdm)
        ret.set_connection(remote, remote_addr)
        return ret

    return construct_transport
