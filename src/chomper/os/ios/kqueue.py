from dataclasses import dataclass

from chomper.os.posix.file import FdEntry


@dataclass
class KQueueEntry(FdEntry):
    path: str = ""
