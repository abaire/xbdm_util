import logging
import time

from . import ip_transport
from . import rdcp_command
from . import rdcp_response

logger = logging.getLogger(__name__)


class XBDMTransport(ip_transport.IPTransport):
    STATE_INIT = 0
    STATE_CONNECTED = 1
    STATE_AWAITING_RESPONSE = 2

    def __init__(self, name=""):
        super().__init__(lambda transport: self._process_xbdm_data(transport), name)

        self._state = self.STATE_INIT
        self._command_queue = []

    @property
    def state(self) -> int:
        return self._state

    @property
    def can_process_commands(self) -> bool:
        return self._state >= self.STATE_CONNECTED

    def send_command(self, cmd: rdcp_command.RDCPCommand) -> bool:
        logger.debug(f"Sending RDCP command {cmd}")
        if self._state < self.STATE_CONNECTED:
            logger.error("Not connected")
            return False

        self._command_queue.append(cmd)
        self._send_next_command()

        return True

    def _send_next_command(self):
        if self._state != self.STATE_CONNECTED or not self._command_queue:
            return
        self.send(self._command_queue[0].serialize())
        self._state = self.STATE_AWAITING_RESPONSE

    def _process_xbdm_data(self, transport: ip_transport.IPTransport):
        cmd = rdcp_response.RDCPResponse()

        bytes_procesed = cmd.parse(transport.read_buffer)
        while bytes_procesed > 0:
            if not self._process_rdcp_command(cmd):
                break
            transport.shift_read_buffer(bytes_procesed)
            bytes_procesed = cmd.parse(transport.read_buffer)

        logger.debug(f"After processing: {transport.read_buffer}")

    def _process_rdcp_command(self, response: rdcp_response.RDCPResponse) -> bool:
        logger.debug(f"Processing RDCP command {response}")
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
            return False
        self._state = self.STATE_CONNECTED
        return True

    def _process_command_response(self, response: rdcp_response.RDCPResponse) -> bool:
        cmd: rdcp_command.RDCPCommand = self._command_queue.pop()
        ret = cmd.process_response(response)

        # TODO: Handle requests to drop connection.
        self._state = self.STATE_CONNECTED
        self._send_next_command()
        return ret
