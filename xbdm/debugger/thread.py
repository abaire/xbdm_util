import struct
from typing import Dict
from typing import Optional

from .xbdm_client import _XBDMClient
from xbdm import rdcp_command
from xbdm.xbdm_bridge import XBDMBridge


def _parse_ext_registers(info: bytes) -> Dict[str, int]:
    (
        control,
        status,
        tag,
        error_offset,
        error_selector,
        data_offset,
        data_selector,
    ) = struct.unpack_from("IIIIIII", info, 0)
    offset = 7 * 4
    registers = info[offset : offset + 80]

    offset += 80
    cr0NpxState = struct.unpack_from("I", info, offset)[0]

    ext_info = {
        "fctrl": control,
        "fstat": status,
        "ftag": tag,
        "fiseg": error_offset,
        "fioff": error_selector,
        "foseg": data_offset,
        "fooff": data_selector,
        "fop": cr0NpxState,
    }

    # Unpack ST0 - ST7
    for i in range(8):
        low_dword, high_word = struct.unpack_from("IH", registers, i * 10)
        ext_info["ST%d" % i] = low_dword + (high_word << 8)

    return ext_info


class Thread(_XBDMClient):
    """Encapsulates information about a thread."""

    class Context:
        """Contains registers for a Thread."""

        def __init__(self, registers: Dict[str, Optional[int]]):
            self.registers = registers

    class FullContext(Context):
        """Contains registers and extended registers for a Thread."""

        def __init__(
            self,
            registers: Dict[str, Optional[int]],
            ext_registers: Optional[bytes] = None,
        ):
            super().__init__(registers)

            self.basic_registers = dict(self.registers)
            self.ext_registers = None
            if ext_registers:
                self.ext_registers = _parse_ext_registers(ext_registers)
                self.registers.update(self.ext_registers)

    _TRAP_FLAG = 0x100

    def __init__(self, thread_id: int, connection: XBDMBridge):
        super().__init__(connection)
        self.thread_id = thread_id

        self.suspend_count: Optional[int] = None
        self.priority: Optional[int] = None
        self.thread_local_storage_addr: Optional[int] = None
        self.start_addr: Optional[int] = None
        self.base_addr: Optional[int] = None
        self.limit: Optional[int] = None
        self.create_time: Optional[int] = None

        self.get_info()

        self.last_known_address: Optional[int] = None
        self.last_stop_reason: Optional[rdcp_command.IsStopped.StopReason] = None

    def __str__(self) -> str:
        lines = [
            f"Thread: {self.thread_id}",
            "  Priority: %d %s"
            % (
                self.priority,
                f"[Suspended {self.suspend_count}]" if self.suspend_count else "",
            ),
            "  Base : 0x%08X" % (self.base_addr or 0),
            "  Start: 0x%08X" % (self.start_addr or 0),
            "  Thread Local Base: 0x%08X" % (self.thread_local_storage_addr or 0),
            "  Limit: 0x%08X" % (self.limit or 0),
            "  CreatedAt: 0x%08X" % (self.create_time or -1),
        ]
        return "\n".join(lines)

    @property
    def last_stop_reason_signal(self) -> int:
        """Returns a signal number representing the reason this thread was last stopped."""
        if not self.last_stop_reason:
            return 0
        return self.last_stop_reason.signal

    def get_info(self):
        response = self._call(rdcp_command.ThreadInfo(self.thread_id))
        if not response.ok:
            raise ConnectionResetError()

        self.suspend_count = response.suspend
        self.priority = response.priority
        self.thread_local_storage_addr = response.tlsbase
        self.start_addr = response.start
        self.base_addr = response.base
        self.limit = response.limit
        # TODO: Convert to a unix timestmap for ease of display.
        self.create_time = response.create

    def get_context(self) -> Optional[Context]:
        registers = self._get_context()
        if not registers:
            return None
        return self.Context(registers)

    def get_full_context(self) -> Optional[FullContext]:
        basic_registers = self._get_context()
        if not basic_registers:
            return None

        ext_registers = None
        response = self._call(rdcp_command.GetExtContext(self.thread_id))
        if response.ok:
            ext_registers = response.data

        return self.FullContext(basic_registers, ext_registers)

    def _get_context(self) -> Optional[Dict[str, Optional[int]]]:
        response = self._call(
            rdcp_command.GetContext(
                self.thread_id,
                enable_float=True,
                enable_control=True,
                enable_integer=True,
            )
        )
        if not response.ok:
            return None
        return response.registers

    def set_step_instruction_mode(self, enabled: bool) -> bool:
        context = self.get_context()
        if not context:
            return False

        old_flags = context.registers["EFlags"]
        if enabled:
            new_flags = old_flags | self._TRAP_FLAG
        else:
            new_flags = old_flags & self._TRAP_FLAG
        if new_flags == old_flags:
            return True

        response = self._call(
            rdcp_command.SetContext(self.thread_id, {"EFlags": new_flags})
        )
        return response.ok

    def prepare_step_function(self) -> bool:
        if not self.halt():
            return False
        if not self._set_step_function():
            return False
        return self.continue_once()

    def _set_step_function(self) -> bool:
        response = self._call(rdcp_command.FuncCall(self.thread_id))
        return response.ok

    def halt(self) -> bool:
        """Sends a 'halt' command."""
        response = self._call(rdcp_command.Halt(self.thread_id))
        if not response.ok:
            return False
        self.get_info()
        return True

    def continue_once(self, break_on_exceptions: bool = True) -> bool:
        """Sends a 'continue' command."""
        response = self._call(
            rdcp_command.Continue(self.thread_id, exception=break_on_exceptions)
        )
        if not response.ok:
            return False
        self.get_info()
        return True

    def suspend(self) -> bool:
        """Sends a 'suspend' command."""
        response = self._call(rdcp_command.Suspend(self.thread_id))
        if not response.ok:
            return False
        self.get_info()
        return True

    def resume(self) -> bool:
        """Sends a 'resume' command."""
        response = self._call(rdcp_command.Resume(self.thread_id))
        if not response.ok:
            return False
        self.get_info()
        return True

    # def unsuspend(self):
    #     """Sends continue commands until suspend count is 0."""
    #     self.get_info()
    #     while self.suspend_count > 0:
    #         self._bridge.send_command(rdcp_command.Continue(self.thread_id))

    def fetch_stop_reason(self) -> bool:
        response = self._call(rdcp_command.IsStopped(self.thread_id))
        if not response:
            return False

        if not response.stopped:
            self.last_stop_reason = None
        else:
            self.last_stop_reason = response.reason
        return True
