from .hooks import CStandardLibraryHooks
from .loader import ELFLoader

from chomper.types import BaseOs


class AndroidOs(BaseOs):
    """The Android environment."""

    def __init__(self, emu, **kwargs):
        super().__init__(emu, **kwargs)

        self.loader = ELFLoader(emu)

    def init_hooks(self):
        """Initialize the hooks."""
        CStandardLibraryHooks.register(self.emu)

    def initialize(self):
        """Initialize the environment."""
        self.init_hooks()
