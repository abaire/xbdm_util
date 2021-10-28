import logging
import sys
from typing import List
from typing import Optional

from . import built_in_commands
from . import commands
from xbdm import rdcp_command
from xbdm.debugger import Debugger
from xbdm.xbdm_bridge import XBDMBridge

logger = logging.getLogger(__name__)


class Shell:
    def __init__(self, bridge: XBDMBridge):
        self._bridge: XBDMBridge = bridge
        self._debugger: Debugger = Debugger(self._bridge)

    def run(self):
        self._print_prompt()

        for line in sys.stdin:
            line = line.strip()
            if not line:
                self._print_prompt()
                continue

            line = line.split(" ")

            command = line[0].lower()
            command_args = line[1:]

            result = self.execute_command(command, command_args)
            if not result:
                break
            self._print_prompt()

    def execute_command(self, command: str, command_args: List[str]) -> bool:
        """Executes a shell command.

        :returns True if further commands should be processed.
        """
        try:
            result = self._handle_shell_command(command, command_args)
        except:
            logger.debug(f"Exception processing shell command: {sys.exc_info()}")
            print("Invalid command")
            return True

        if result == built_in_commands.Result.EXIT_REQUESTED:
            if self._debugger:
                self._debugger.shutdown()
            return False

        if result == built_in_commands.Result.HANDLED:
            return True

        try:
            processor = commands.DISPATCH_TABLE.get(command)
            if not processor:
                print("Invalid command")
            else:
                cmd = processor(command_args)

                # Hack: Intercept the command to see if it is a NotifyAt and
                # stand up a listener if necessary.
                if command == "notifyat" and isinstance(cmd, rdcp_command.NotifyAt):
                    self._handle_notifyat(cmd.address, cmd.port, cmd.drop, cmd.debug)

                if cmd:
                    self._bridge.send_command(cmd)

                # Hack: Wait for a graceful close and exit.
                if command == "bye":
                    self._bridge.await_empty_queue()
                    return False

        except IndexError:
            print("Missing required parameter.")
        except ValueError as e:
            print(f"Incorrect type.\n{e}")
        except ConnectionResetError:
            print("Connection closed by XBOX")
            if not self._bridge.reconnect():
                print("Failed to reconnect")
                return False

        self._bridge.await_empty_queue()

        return True

    def attach_debugger(self) -> Debugger:
        self._debugger.attach()
        return self._debugger

    def _handle_notifyat(
        self, address: Optional[str], port: int, is_drop: bool, is_debug: bool
    ):
        del is_debug

        if address:
            return
        if is_drop:
            # TODO: Shut down the notification listener?
            return

        logger.info(f"Starting notifyat listener at {port}")
        self._bridge.create_notification_listener(port)

    def _print_prompt(self) -> None:
        if self._debugger:
            print(f"dbg {self._debugger.short_state_info}> ", end="")
        else:
            print("> ", end="")
        sys.stdout.flush()

    def _handle_shell_command(
        self, command: str, args: [str]
    ) -> built_in_commands.Result:
        handler = built_in_commands.DISPATCH_TABLE.get(command.lower())
        if not handler:
            return built_in_commands.Result.NOT_HANDLED

        return handler(self, args)
