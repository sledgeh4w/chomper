from chomper.base import BaseOs
from chomper.os.android.hooks import get_hooks
from chomper.os.android.loader import ELFLoader


class AndroidOs(BaseOs):
    """Provide Android runtime environment."""

    def __init__(self, emu, **kwargs):
        super().__init__(emu, **kwargs)

        self.loader = ELFLoader(emu)

        self._setup_hooks()

    def _setup_hooks(self):
        """Initialize the hooks."""
        self.emu.hooks.update(get_hooks())

    def initialize(self):
        """Initialize the environment."""
        self._setup_hooks()
