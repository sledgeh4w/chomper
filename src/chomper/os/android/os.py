from chomper.abc import BaseOs
from chomper.os.android.hooks import hooks
from chomper.os.android.loader import ELFLoader


class AndroidOs(BaseOs):
    """Provide Android runtime environment."""

    def __init__(self, emu, **kwargs):
        super().__init__(emu, **kwargs)

        self.loader = ELFLoader(emu)

    def _setup_hooks(self):
        """Initialize the hooks."""
        self.emu.hooks.update(hooks)

    def initialize(self):
        """Initialize the environment."""
        self._setup_hooks()
