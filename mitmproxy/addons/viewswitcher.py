import typing 
from mitmproxy import command
import mitmproxy.types

views = ["flowview",
         "flowlist",
         "eventlog"]

class ViewSwitcher():
    @command.command("view.switcher.views")
    def views(self) -> typing.Sequence[str]:
        """
            Return a list of the supported export formats.
        """
        return list(sorted(views))

