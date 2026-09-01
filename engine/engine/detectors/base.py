from ..schema import Alert, Flow


class Detector:
    """Base class for threat detectors.

    Each detector keeps its own stateful windows inside the shared
    WindowStore and returns zero or more Alerts per processed flow.
    """

    def __init__(self, ctx):
        self.ctx = ctx

    def process(self, flow: Flow) -> list[Alert]:  # pragma: no cover - interface
        raise NotImplementedError
