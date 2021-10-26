import collections
import logging
import socket
from typing import Tuple

from net import ip_transport
from . import xbdm_notification_transport
from . import rdcp_command
from . import rdcp_response
import util

logger = logging.getLogger(__name__)

logging.Logger.xbdm = util.register_colorized_logging_level(
    "XBDM", util.ANSI_CYAN + util.ANSI_BRIGHT_WHITE_BACKGROUND + util.ANSI_BOLD
)
logging.Logger.xbdm_send = util.register_colorized_logging_level(
    "<< XBDM",
    util.ANSI_CYAN
    + util.ANSI_BRIGHT_WHITE_BACKGROUND
    + util.ANSI_UNDERLINE
    + util.ANSI_BOLD,
)
logging.Logger.xbdm_debug = util.register_colorized_super_verbose_logging_level(
    "XBDMDBG", util.ANSI_CYAN + util.ANSI_WHITE_BACKGROUND
)


class XBDMTransport(ip_transport.IPTransport):
    STATE_INIT = 0
    STATE_CONNECTED = 1
    STATE_AWAITING_RESPONSE = 2

    def __init__(self, name=""):
        super().__init__(self._process_xbdm_data, name)

        self._state = self.STATE_INIT
        self._command_queue = collections.deque()

    @property
    def state(self) -> int:
        return self._state

    @property
    def can_process_commands(self) -> bool:
        return self._state >= self.STATE_CONNECTED

    @property
    def has_buffered_data(self) -> bool:
        # TODO: Make this thread safe.
        return self._command_queue or self._read_buffer or self._write_buffer

    def debug__notify_connected(self):
        """Sets the state to STATE_CONNECTED if the socket is connected.

        This is necessary as XBDM will not send a connection event when restarting with a debug notification channel already in place.
        """
        if not self.connected or self.can_process_commands:
            return
        self._state = self.STATE_CONNECTED

    def send_command(self, cmd: rdcp_command.RDCPCommand) -> bool:
        logger.xbdm_send(f"Queueing RDCP command {cmd}")
        if self._state < self.STATE_CONNECTED:
            logger.error("Not connected")
            return False

        self._command_queue.append(cmd)
        self._send_next_command()

        return True

    def close(self):
        super().close()
        self._state = self.STATE_INIT

    def _send_next_command(self):
        if self._state != self.STATE_CONNECTED or not self._command_queue:
            return
        bytes = self._command_queue[0].serialize()
        logger.xbdm_debug(f"Sending RDCP {bytes}")
        self.send(bytes)
        self._state = self.STATE_AWAITING_RESPONSE

    def _process_xbdm_data(self, transport: ip_transport.IPTransport):
        response = rdcp_response.RDCPResponse()

        def parse_response() -> Tuple[rdcp_command.RDCPCommand, int]:
            current_command = None
            if self._command_queue:
                current_command = self._command_queue[0]

            if not current_command:
                binary_response_length = response.BINARY_NO_BINARY_ALLOWED
            else:
                binary_response_length = current_command.expected_binary_response_length

            bytes_procesed = response.parse(
                transport.read_buffer, binary_response_length
            )
            return current_command, bytes_procesed

        current_command, bytes_processed = parse_response()

        while bytes_processed > 0:
            # If the response expects binary data, insert a new RDCPBinaryPayload instance for the command just after the current command.
            if response.status == response.STATUS_SEND_BINARY_DATA:
                payload = rdcp_command.RDCPBinaryPayload(current_command)
                self._command_queue.insert(1, payload)

            if self._process_rdcp_command(response):
                logger.warning(
                    f"!!! Close requested when processing response {response}"
                )
                break
            transport.shift_read_buffer(bytes_processed)

            if response.status == response.STATUS_CONNECTION_DEDICATED:
                if not current_command.dedicate_notification_mode:
                    logger.error("Unexpected request to dedicate connection.")
                    # TODO: Shut down the connection and start a new one?
                else:
                    self._create_dedicated_connection(
                        xbdm_notification_transport.XBDMNotificationTransport
                    )
                    break

            current_command, bytes_processed = parse_response()

        logger.xbdm_debug(
            f"After processing: [{len(transport.read_buffer)}] {transport.read_buffer}"
        )

    def _create_dedicated_connection(self, transport_constructor):
        """Passes the current socket to a new dedicated connection handler and reconnects to the remote."""
        new_conn = transport_constructor(
            self.name, self._sock, self.addr, self._read_buffer
        )
        self._add_sub_connection(new_conn)
        self._sock = socket.create_connection(self.addr)
        self._state = self.STATE_INIT
        self._read_buffer = bytearray()

    def _process_rdcp_command(self, response: rdcp_response.RDCPResponse) -> bool:
        """Processes a single RDCPResponse. Return True to close the connection"""
        logger.xbdm(f"Processing RDCP command {response}")
        if self._state == self.STATE_INIT:
            return self._process_connect_response(response)
        elif self._state == self.STATE_AWAITING_RESPONSE:
            return self._process_command_response(response)
        return True

    def _process_connect_response(self, response: rdcp_response.RDCPResponse) -> bool:
        if (
            response.status != response.STATUS_OK
            and response.status != response.STATUS_CONNECTED
        ):
            return True
        self._state = self.STATE_CONNECTED
        logger.xbdm(f"Connect response: {response.data.decode('utf-8')}")
        return False

    def _process_command_response(self, response: rdcp_response.RDCPResponse) -> bool:
        cmd: rdcp_command.RDCPCommand = self._command_queue.popleft()
        ret = cmd.process_response(response)

        # TODO: Handle requests to drop connection.
        self._state = self.STATE_CONNECTED
        self._send_next_command()
        return ret
