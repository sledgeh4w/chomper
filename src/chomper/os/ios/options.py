from chomper.types import Options


class IosOptions(Options):
    """Options of the iOS environment.

    Args:
        enable_objc: Enable Objective-C support. Defaults to True.
        enable_ui_kit: Enable UIKit support. Defaults to False.
    """

    def __init__(self, enable_objc: bool = True, enable_ui_kit: bool = False):
        self.enable_objc = enable_objc
        self.enable_ui_kit = enable_ui_kit
