"""
The View:

- Keeps track of a store of flows
- Maintains a filtered, ordered view onto that list of flows
- Exposes a number of signals so the view can be monitored
- Tracks focus within the view
- Exposes a settings store for flows that automatically expires if the flow is
  removed from the store.
"""
import collections
import typing

import blinker
import sortedcontainers

import mitmproxy.flow
from mitmproxy import tcp
from mitmproxy import flowfilter
from mitmproxy import exceptions
from mitmproxy import command
from mitmproxy import connections
from mitmproxy import ctx
from mitmproxy.addons import view
from mitmproxy import io

# The underlying sorted list implementation expects the sort key to be stable
# for the lifetime of the object. However, if we sort by size, for instance,
# the sort order changes as the flow progresses through its lifecycle. We
# address this through two means:
#
# - Let order keys cache the sort value by flow ID.
#
# - Add a facility to refresh items in the list by removing and re-adding them
# when they are updated.

class OrderRequestStart(view._OrderKey):
    def generate(self, f) -> int:
        return 1
        return f.request.timestamp_start or 0


class OrderRequestMethod(view._OrderKey):
    def generate(self, f) -> str:
        return f.request.method


class OrderRequestURL(view._OrderKey):
    def generate(self, f) -> str:
        return f.request.url


class OrderKeySize(view._OrderKey):
    def generate(self, f) -> int:
        s = 0
        if f.request.raw_content:
            s += len(f.request.raw_content)
        if f.response and f.response.raw_content:
            s += len(f.response.raw_content)
        return s


matchall = flowfilter.parse(".")


orders = [
    ("t", "time"),
    ("m", "method"),
    ("u", "url"),
    ("z", "size"),
]


class TCPView(view.View):
    def __init__(self):
        super().__init__()
        self._store = collections.OrderedDict()
        self.filter = matchall
        # Should we show only marked flows?
        self.show_marked = False

        self.default_order = OrderRequestStart(self)
        self.orders = dict(
            time = OrderRequestStart(self), method = OrderRequestMethod(self),
            url = OrderRequestURL(self), size = OrderKeySize(self),
        )
        self.order_key = self.default_order
        self.order_reversed = False
        self.focus_follow = False

        self._view = sortedcontainers.SortedListWithKey(
            key = self.order_key
        )

        # The sig_view* signals broadcast events that affect the view. That is,
        # an update to a flow in the store but not in the view does not trigger
        # a signal. All signals are called after the view has been updated.
        self.sig_view_update = blinker.Signal()
        self.sig_view_add = blinker.Signal()
        self.sig_view_remove = blinker.Signal()
        # Signals that the view should be refreshed completely
        self.sig_view_refresh = blinker.Signal()

        # The sig_store* signals broadcast events that affect the underlying
        # store. If a flow is removed from just the view, sig_view_remove is
        # triggered. If it is removed from the store while it is also in the
        # view, both sig_store_remove and sig_view_remove are triggered.
        self.sig_store_remove = blinker.Signal()
        # Signals that the store should be refreshed completely
        self.sig_store_refresh = blinker.Signal()

        self.focus = view.Focus(self)
        self.settings = view.Settings(self)

    def load(self, loader):
        loader.add_option(
            "view_filter", typing.Optional[str], None,
            "Limit the view to matching flows."
        )
        loader.add_option(
            "view_order", str, "time",
            "Flow sort order.",
            choices=list(map(lambda c: c[1], orders)),
        )
        loader.add_option(
            "view_order_reversed", bool, False,
            "Reverse the sorting order."
        )
        loader.add_option(
            "console_focus_follow", bool, False,
            "Focus follows new flows."
        )

    def store_count(self):
        return len(self._store)

    def _rev(self, idx: int) -> int:
        """
            Reverses an index, if needed
        """
        if self.order_reversed:
            if idx < 0:
                idx = -idx - 1
            else:
                idx = len(self._view) - idx - 1
                if idx < 0:
                    raise IndexError
        return idx

    def __len__(self):
        return len(self._view)

    def __getitem__(self, offset) -> typing.Any:
        return self._view[self._rev(offset)]

    # Reflect some methods to the efficient underlying implementation

    def _bisect(self, f: mitmproxy.flow.Flow) -> int:
        v = self._view.bisect_right(f)
        return self._rev(v - 1) + 1

    def index(self, f: mitmproxy.flow.Flow, start: int = 0, stop: typing.Optional[int] = None) -> int:
        return self._rev(self._view.index(f, start, stop))

    def __contains__(self, f: typing.Any) -> bool:
        return self._view.__contains__(f)

    def _order_key_name(self):
        return "_order_%s" % id(self.order_key)

    def _base_add(self, f):
        self.settings[f][self._order_key_name()] = self.order_key(f)
        self._view.add(f)

    def _refilter(self):
        self._view.clear()
        for i in self._store.values():
            if self.show_marked and not i.marked:
                continue
            if self.filter(i):
                self._base_add(i)
        self.sig_view_refresh.send(self)

    """ View API """

    @command.command("view.order")
    def get_order(self) -> str:
        """
        Returns the current view order.
        """
        order = ""
        for k in self.orders.keys():
            if self.order_key == self.orders[k]:
                order = k
        return order


    @command.command("view.flows.create")
    def create(self, method: str, url: str) -> None:
        pass
       #try:
       #    req = http.HTTPRequest.make(method.upper(), url)
       #except ValueError as e:
       #    raise exceptions.CommandError("Invalid URL: %s" % e)
       #c = connections.ClientConnection.make_dummy(("", 0))
       #s = connections.ServerConnection.make_dummy((req.host, req.port))
       #f = http.HTTPFlow(c, s)
       #f.request = req
       #f.request.headers["Host"] = req.host
       #self.add([f])

    @command.command("view.flows.load")
    def load_file(self, path: mitmproxy.types.Path) -> None:
        """
            Load flows into the view, without processing them with addons.
        """
        try:
            with open(path, "rb") as f:
                for i in io.FlowReader(f).stream():
                    # Do this to get a new ID, so we can load the same file N times and
                    # get new flows each time. It would be more efficient to just have a
                    # .newid() method or something.
                    self.add([i.copy()])
        except IOError as e:
            ctx.log.error(e.strerror)
        except exceptions.FlowReadException as e:
            ctx.log.error(str(e))

    def add(self, flows: typing.Sequence[mitmproxy.flow.Flow]) -> None:
        """
            Adds a flow to the state. If the flow already exists, it is
            ignored.
        """
        import pdb;pdb.set_trace()
        for f in flows:
            if f.id not in self._store:
                self._store[f.id] = f
                if self.filter(f):
                    self._base_add(f)
                    if self.focus_follow:
                        self.focus.flow = f
                    self.sig_view_add.send(self, flow=f)


    # Event handlers
    def configure(self, updated):
        if "view_filter" in updated:
            filt = None
            if ctx.options.view_filter:
                filt = flowfilter.parse(ctx.options.view_filter)
                if not filt:
                    raise exceptions.OptionsError(
                        "Invalid interception filter: %s" % ctx.options.view_filter
                    )
            self.set_filter(filt)
        if "view_order" in updated:
            if ctx.options.view_order not in self.orders:
                raise exceptions.OptionsError(
                    "Unknown flow order: %s" % ctx.options.view_order
                )
            self.set_order(ctx.options.view_order)
        if "view_order_reversed" in updated:
            self.set_reversed(ctx.options.view_order_reversed)
        if "console_focus_follow" in updated:
            self.focus_follow = ctx.options.console_focus_follow

    def tcp_start(self, f: tcp.TCPFlow):
        self.add([f])

    def tcp_message(self, f: tcp.TCPFlow):
        self.add([f])

    def request(self, f):
        pass

    def error(self, f):
        self.update([f])

    def response(self, f):
        self.update([f])

    def intercept(self, f):
        self.update([f])

    def resume(self, f):
        self.update([f])

    def kill(self, f):
        self.update([f])

    def update(self, flows: typing.Sequence[mitmproxy.flow.Flow]) -> None:
        """
            Updates a list of flows. If flow is not in the state, it's ignored.
        """
        for f in flows:
            if f.id in self._store:
                if self.filter(f):
                    if f not in self._view:
                        self._base_add(f)
                        if self.focus_follow:
                            self.focus.flow = f
                        self.sig_view_add.send(self, flow=f)
                    else:
                        # This is a tad complicated. The sortedcontainers
                        # implementation assumes that the order key is stable. If
                        # it changes mid-way Very Bad Things happen. We detect when
                        # this happens, and re-fresh the item.
                        self.order_key.refresh(f)
                        self.sig_view_update.send(self, flow=f)
                else:
                    try:
                        idx = self._view.index(f)
                    except ValueError:
                        pass  # The value was not in the view
                    else:
                        self._view.remove(f)
                        self.sig_view_remove.send(self, flow=f, index=idx)
