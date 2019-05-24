import collections
import typing
import mitmproxy.flow

class Settings(collections.abc.Mapping):
    def __init__(self, view ) -> None:
        self.view = view
        self._values: typing.MutableMapping[str, typing.Dict] = {}
        view.sig_store_remove.connect(self._sig_store_remove)
        view.sig_store_refresh.connect(self._sig_store_refresh)

    def __iter__(self) -> typing.Iterator:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __getitem__(self, f: mitmproxy.flow.Flow) -> dict:
        if f.id not in self.view._store:
            raise KeyError
        return self._values.setdefault(f.id, {})

    def _sig_store_remove(self, view, flow):
        if flow.id in self._values:
            del self._values[flow.id]

    def _sig_store_refresh(self, view):
        for fid in list(self._values.keys()):
            if fid not in view._store:
                del self._values[fid]
