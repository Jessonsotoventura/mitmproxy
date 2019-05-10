import urwid

from mitmproxy.tools.console import common
from mitmproxy.tools.console import layoutwidget
from mitmproxy.tools.console import flowlist
import mitmproxy.tools.console.master # noqa


class TCPItem(flowlist.FlowItem):

    def get_text(self):
        cols, _ = self.master.ui.get_cols_rows()
        return common.format_flow(
            self.flow,
            self.flow is self.master.view.focus.flow,
            hostheader=self.master.options.showhost,
            max_url_len=cols,
        )

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            if self.flow.request:
                self.master.commands.execute("console.view.flow @focus")
                return True


class TCPListWalker(flowlist.FlowListWalker):
    pass

class TCPListBox(flowlist.FlowListBox):

    title = "TCP Flows"
    keyctx = "tcplist"

    def keypress(self, size, key):
        if key == "m_start":
            self.master.commands.execute("view.focus.go 0")
        elif key == "m_end":
            self.master.commands.execute("view.focus.go -1")
        elif key == "m_select":
            self.master.commands.execute("console.view.tcp @focus")
        return urwid.ListBox.keypress(self, size, key)
