import logging

from . import ip_transport

logger = logging.getLogger(__name__)


class NotificationTransport(ip_transport.IPTransport):
    """Takes ownership of a socket and reads it in notification mode."""

    TERMINATOR = b"\r\n"

    def __init__(self, transport: ip_transport.IPTransport):
        super().__init__(self._process_notification_data, f"! {transport.name}")

        # Take over the socket from the existing transport.
        self._sock = transport._sock
        self.addr = transport.addr
        self._read_buffer = transport._read_buffer

    def _process_notification_data(self, transport: ip_transport.IPTransport):
        terminator_len = len(self.TERMINATOR)
        terminator = transport.read_buffer.find(self.TERMINATOR)
        while terminator >= 0:
            message = transport.read_buffer[:terminator]
            print(f"{self.name}: {message.decode('utf-8')}")

            transport.shift_read_buffer(terminator + terminator_len)
            terminator = transport.read_buffer.find(self.TERMINATOR)
