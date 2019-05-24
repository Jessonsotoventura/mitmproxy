import typing

from mitmproxy import http  # noqa


class _OrderKey:
    def __init__(self, view):
        self.view = view

    def generate(self, f: http.HTTPFlow) -> typing.Any:  # pragma: no cover
        pass

    def refresh(self, f):
        k = self._key()
        old = self.view.settings[f][k]
        new = self.generate(f)
        if old != new:
            self.view._view.remove(f)
            self.view.settings[f][k] = new
            self.view._view.add(f)
            self.view.sig_view_refresh.send(self.view)

    def _key(self):
        return "_order_%s" % id(self)

    def __call__(self, f):
        if f.id in self.view._store:
            k = self._key()
            s = self.view.settings[f]
            if k in s:
                return s[k]
            val = self.generate(f)
            s[k] = val
            return val
        else:
            return self.generate(f)


class OrderRequestStart(_OrderKey):
    def generate(self, f: http.HTTPFlow) -> int:
        #TPDP
        return f.client.conn.timestamp_start
        return f.request.timestamp_start or 0


class OrderRequestMethod(_OrderKey):
    def generate(self, f: http.HTTPFlow) -> str:
        return f.request.method


class OrderRequestURL(_OrderKey):
    def generate(self, f: http.HTTPFlow) -> str:
        return f.request.url


class OrderKeySize(_OrderKey):
    def generate(self, f: http.HTTPFlow) -> int:
        s = 0
        if f.request.raw_content:
            s += len(f.request.raw_content)
        if f.response and f.response.raw_content:
            s += len(f.response.raw_content)
        return s
