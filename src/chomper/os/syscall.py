from __future__ import annotations

import abc
from abc import ABC
from typing import Callable, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from chomper.core import Chomper


class BaseSyscallHandler(ABC):
    """Base class for Handling system calls."""

    def __init__(self, emu: Chomper):
        self.emu = emu

        self._names: Dict[int, str] = {}
        self._handlers: Dict[int, Callable] = {}

    @abc.abstractmethod
    def _syscall_wrapper(self, handler: Callable):
        pass

    def handle_syscall(self, syscall_no: int):
        syscall_name = self._names.get(syscall_no)
        syscall_display = f"'{syscall_name}'" if syscall_name else hex(syscall_no)
        from_addr = self.emu.debug_symbol(self.emu.uc.reg_read(self.emu.arch.reg_pc))

        self.emu.logger.info(f"System call {syscall_display} invoked from {from_addr}")

        if syscall_no not in self._handlers:
            self.emu.crash(f"Unhandled system call {syscall_display}")

        result = self._syscall_wrapper(self._handlers[syscall_no])
        if result is not None:
            self.emu.set_retval(result)
