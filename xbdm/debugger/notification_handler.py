from .module import Module
from .section import Section


class NotificationHandler:
    """Handles asynchronous notifications from XBDM."""

    def debugstr(self, _thread_id: int, _text: str):
        pass

    def vx(self, _message: str):
        pass

    def module_load(self, _mod: Module):
        pass

    def section_load(self, _sect: Section):
        pass

    def create_thread(self, _thread_id: int, _start_address: int):
        pass

    def terminate_thread(self, _thread_id: int):
        pass

    def execution_state_change(self, _new_state: str):
        pass

    def breakpoint(self, _thread_id: int, _address: int, _reason: str):
        pass

    def data_breakpoint(
        self,
        _thread_id: int,
        _access: str,
        _access_address: int,
        _address: int,
        _reason: str,
    ):
        pass

    def step(self, _thread_id: int, _address: int):
        pass

    def exception(
        self, _thread_id: int, _code: int, _address: int, _read: int, _extra: str
    ):
        pass


class DefaultNotificationHandler(NotificationHandler):
    """Default notification handler that just prints to the console."""

    def debugstr(self, thread_id: int, text: str):
        print("DBG[%03d]> %s" % (thread_id, text))

    def vx(self, message: str):
        print(f"vx: {message}")

    def module_load(self, mod: Module):
        print(f"Loaded module: {mod}")

    def section_load(self, sect: Section):
        print(f"Loaded section: {sect}")

    def create_thread(self, thread_id: int, start_address: int):
        print(f"Created thread: {thread_id} start_addr: 0x%08X" % start_address)

    def terminate_thread(self, thread_id: int):
        print(f"Terminate thread: {thread_id}")

    def execution_state_change(self, new_state: str):
        print(f"EXECUTION STATE CHANGE: {new_state}")

    def breakpoint(self, thread_id: int, address: int, reason: str):
        print("BREAK: %d @ 0x%X %s" % (thread_id, address, reason))

    def data_breakpoint(
        self,
        thread_id: int,
        access: str,
        access_address: int,
        address: int,
        reason: str,
    ):
        print(
            "DATA BREAK: %d: %s@0x%08X @ 0x%X %s"
            % (thread_id, access, access_address, address, reason)
        )

    def step(self, thread_id: int, address: int):
        print("STEP: %d @ 0x%X" % (thread_id, address))

    def exception(self, thread_id: int, code: int, address: int, read: int, extra: str):
        print(
            "EXCEPTION %d code 0x%X @ 0x%X read: 0x%X extra: '%s'"
            % (thread_id, code, address, read, extra)
        )


class RedirectingNotificationHandler(NotificationHandler):
    """Redirects notifications to callbacks passed in init."""

    def __init__(
        self,
        on_debugstr=None,
        on_vx=None,
        on_module_load=None,
        on_section_load=None,
        on_create_thread=None,
        on_terminate_thread=None,
        on_execution_state_change=None,
        on_breakpoint=None,
        on_data_breakpoint=None,
        on_step=None,
        on_exception=None,
    ):
        super().__init__()

        def default_handler(*args):
            pass

        self.on_debugstr = on_debugstr if on_debugstr else default_handler
        self.on_vx = on_vx if on_vx else default_handler
        self.on_module_load = on_module_load if on_module_load else default_handler
        self.on_section_load = on_section_load if on_section_load else default_handler
        self.on_create_thread = (
            on_create_thread if on_create_thread else default_handler
        )
        self.on_terminate_thread = (
            on_terminate_thread if on_terminate_thread else default_handler
        )
        self.on_execution_state_change = (
            on_execution_state_change if on_execution_state_change else default_handler
        )
        self.on_breakpoint = on_breakpoint if on_breakpoint else default_handler
        self.on_data_breakpoint = (
            on_data_breakpoint if on_data_breakpoint else default_handler
        )
        self.on_step = on_step if on_step else default_handler
        self.on_exception = on_exception if on_exception else default_handler

    def debugstr(self, thread_id: int, text: str):
        self.on_debugstr(thread_id, text)

    def vx(self, message: str):
        self.on_vx(message)

    def module_load(self, mod: Module):
        self.on_module_load(mod)

    def section_load(self, sect: Section):
        self.on_section_load(sect)

    def create_thread(self, thread_id: int, start_address: int):
        self.on_create_thread(thread_id, start_address)

    def terminate_thread(self, thread_id: int):
        self.on_terminate_thread(thread_id)

    def execution_state_change(self, new_state: str):
        self.on_execution_state_change(new_state)

    def breakpoint(self, thread_id: int, address: int, reason: str):
        self.on_breakpoint(thread_id, address, reason)

    def data_breakpoint(
        self,
        thread_id: int,
        access: str,
        access_address: int,
        address: int,
        reason: str,
    ):
        self.on_data_breakpoint(thread_id, access, access_address, address, reason)

    def step(self, thread_id: int, address: int):
        self.on_step(thread_id, address)

    def exception(self, thread_id: int, code: int, address: int, read: int, extra: str):
        self.on_exception(thread_id, code, address, read, extra)
