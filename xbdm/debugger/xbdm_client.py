from xbdm import rdcp_command
from xbdm.xbdm_bridge import XBDMBridge


class _XBDMClient:
    """Provides functionality for communicating with an XBDMBridge."""

    def __init__(self, connection: XBDMBridge):
        self._bridge: XBDMBridge = connection

    def _call(
        self, cmd: rdcp_command.ProcessedCommand
    ) -> rdcp_command.ProcessedResponseCatcher:
        """Sends a command to the underlying connection and waits for the response."""
        response = self._call_async(cmd)
        self._bridge.await_empty_queue()
        return response

    def _call_async(
        self, cmd: rdcp_command.ProcessedCommand
    ) -> rdcp_command.ProcessedResponseCatcher:
        """Sends a command to the underlying connection and immediately returns a handler that will eventually receive the result."""
        response = rdcp_command.ProcessedResponseCatcher()
        cmd.set_handler(response)
        self._bridge.send_command(cmd)
        return response
