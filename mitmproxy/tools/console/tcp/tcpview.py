import math
import sys
from functools import lru_cache
from typing import Optional, Union  # noqa

import urwid

from mitmproxy import contentviews
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import tcp
from mitmproxy.tools.console import common
from mitmproxy.tools.console import layoutwidget
from mitmproxy.tools.console import flowdetailview
from mitmproxy.tools.console import searchable
from mitmproxy.tools.console import tabs
import mitmproxy.tools.console.master  # noqa
from mitmproxy.utils import strutils


class SearchError(Exception):
    pass


class TCPViewHeader(urwid.WidgetWrap):

    def __init__(
        self,
        master: "mitmproxy.tools.console.master.ConsoleMaster",
    ) -> None:
        self.master = master
        self.focus_changed()

    def focus_changed(self):
        cols, _ = self.master.ui.get_cols_rows()
        if self.master.view.focus.flow:
            self._w = common.format_flow(
                self.master.view.focus.flow,
                False,
                extended=True,
                hostheader=self.master.options.showhost,
                max_url_len=cols,
            )
        else:
            self._w = urwid.Pile([])


class TCPDetails(tabs.Tabs):
    def __init__(self, master):
        self.master = master
        super().__init__([])
        self.show()
        self.last_displayed_body = None

    def focus_changed(self):
        if self.master.tcpview.focus.flow:
            self.tabs = [
                (self.tab_tcp_unified, self.view_tcp_unified),
                (self.tab_tcp_client, self.view_tcp_client),
                (self.tab_tcp_server, self.view_tcp_server),
            ]
            self.show()
        else:
            self.master.window.pop()

    @property
    def view(self):
        return self.master.view

    @property
    def flow(self):
        return self.master.view.focus.flow

    def tab_tcp_client(self):
        return "Client"

    def tab_tcp_server(self):
        return "Server"

    def tab_tcp_unified(self):
        return "Unified"

    def view_tcp_client(self):
        return self.conn_text(self.flow.client)

    def view_tcp_server(self):
        return self.conn_text(self.flow.server)

    def view_tcp_unified(self):
        return self.conn_text(self.flow)

    def content_view(self, viewmode, message):
        if message.messages is None:
            msg, body = "", [urwid.Text([("error", "[content missing]")])]
            return msg, body
        else:
            full = self.master.commands.execute("view.settings.getval @focus fullcontents false")
            if full == "true":
                limit = sys.maxsize
            else:
                limit = ctx.options.content_view_lines_cutoff

            flow_modify_cache_invalidation = None

            if isinstance(message, tcp.TCPFlow):
                flow_modify_cache_invalidation = hash((
                    message.raw_content,
                    message.server.conn.address,
                    message.client.conn.address,
                ))
            else:
                flow_modify_cache_invalidation = hash((
                    message.raw_content,
                    message.conn.address,
                ))

            # we need to pass the message off-band because it's not hashable
            self._get_content_view_message = message
            return self._get_content_view(viewmode, limit, flow_modify_cache_invalidation)

    @lru_cache(maxsize=200)
    def _get_content_view(self, viewmode, max_lines, _):
        message = self._get_content_view_message
        self._get_content_view_message = None
        description, lines, error = contentviews.get_message_content_view(
            viewmode, message
        )
        if error:
            self.master.log.debug(error)
        # Give hint that you have to tab for the response.
        if description == "No content" and isinstance(message, http.HTTPRequest):
            description = "No request content (press tab to view response)"

        # If the users has a wide terminal, he gets fewer lines; this should not be an issue.
        chars_per_line = 80
        max_chars = max_lines * chars_per_line
        total_chars = 0
        text_objects = []
        for line in lines:
            txt = []
            for (style, text) in line:
                if total_chars + len(text) > max_chars:
                    text = text[:max_chars - total_chars]
                txt.append((style, text))
                total_chars += len(text)
                if total_chars == max_chars:
                    break

            # round up to the next line.
            total_chars = int(math.ceil(total_chars / chars_per_line) * chars_per_line)

            text_objects.append(urwid.Text(txt))
            if total_chars == max_chars:
                text_objects.append(urwid.Text([
                    ("highlight", "Stopped displaying data after %d lines. Press " % max_lines),
                    ("key", "f"),
                    ("highlight", " to load all data.")
                ]))
                break

        return description, text_objects

    def conn_text(self, conn):
        if conn:
            hdrs = []
            txt = common.format_keyvals(
                hdrs,
                key_format="header"
            )
            viewmode = self.master.commands.call("console.tcpview.mode")
            msg, body = self.content_view(viewmode, conn)

            cols = [
                urwid.Text(
                    [
                        ("heading", msg),
                    ]
                ),
                urwid.Text(
                    [
                        " ",
                        ('heading', "["),
                        ('heading_key', "m"),
                        ('heading', (":%s]" % viewmode)),
                    ],
                    align="right"
                )
            ]
            title = urwid.AttrWrap(urwid.Columns(cols), "heading")

            txt.append(title)
            txt.extend(body)
        else:
            txt = [
                urwid.Text(""),
                urwid.Text(
                    [
                        ("highlight", "No response. Press "),
                        ("key", "e"),
                        ("highlight", " and edit any aspect to add one."),
                    ]
                )
            ]
        return searchable.Searchable(txt)


class TCPView(urwid.Frame, layoutwidget.LayoutWidget):
    keyctx = "tcpview"
    title = "TCP Flow Details"

    def __init__(self, master):
        super().__init__(
            TCPDetails(master),
            header = TCPViewHeader(master),
        )
        self.master = master

    def focus_changed(self, *args, **kwargs):
        self.body.focus_changed()
        self.header.focus_changed()
