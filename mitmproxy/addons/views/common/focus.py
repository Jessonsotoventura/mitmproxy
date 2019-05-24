import typing
import blinker

import mitmproxy.flow
from mitmproxy import http  # noqa

class Focus:
    """
        Tracks a focus element within a View.
    """
    def __init__(self, v) -> None:
        self.view = v
        self._flow: mitmproxy.flow.Flow = None
        self.sig_change = blinker.Signal()
        if len(self.view):
            self.flow = self.view[0]
        v.sig_view_add.connect(self._sig_view_add)
        v.sig_view_remove.connect(self._sig_view_remove)
        v.sig_view_refresh.connect(self._sig_view_refresh)

    @property
    def flow(self) -> typing.Optional[mitmproxy.flow.Flow]:
        return self._flow

    @flow.setter
    def flow(self, f: typing.Optional[mitmproxy.flow.Flow]):
        if f is not None and f not in self.view:
            raise ValueError("Attempt to set focus to flow not in view")
        self._flow = f
        self.sig_change.send(self)

    @property
    def index(self) -> typing.Optional[int]:
        if self.flow:
            return self.view.index(self.flow)
        return None

    @index.setter
    def index(self, idx):
        if idx < 0 or idx > len(self.view) - 1:
            raise ValueError("Index out of view bounds")
        self.flow = self.view[idx]

    def _nearest(self, f, v):
        return min(v._bisect(f), len(v) - 1)

    def _sig_view_remove(self, view, flow, index):
        if len(view) == 0:
            self.flow = None
        elif flow is self.flow:
            self.index = min(index, len(self.view) - 1)

    def _sig_view_refresh(self, view):
        if len(view) == 0:
            self.flow = None
        elif self.flow is None:
            self.flow = view[0]
        elif self.flow not in view:
            self.flow = view[self._nearest(self.flow, view)]

    def _sig_view_add(self, view, flow):
        # We only have to act if we don't have a focus element
        if not self.flow:
            self.flow = flow
