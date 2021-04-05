# uncompyle6 version 3.7.4
# Python bytecode 3.8 (3413)
# Decompiled from: Python 3.7.9 (default, Dec 21 2020, 21:28:54) 
# [GCC 10.2.0]
# Embedded file name: /home/jesson/Projects/mitmproxy/mitmproxy/tools/console/tests.py
# Compiled at: 2020-12-15 14:04:49
# Size of source mod 2**32: 482 bytes
import typing, urwid, mitmproxy.flow
from mitmproxy import http
from mitmproxy.tools.console import common, searchable
from mitmproxy.utils import human
from mitmproxy.utils import strutils

def draw_app_tests(data):
    hdrs = []
    for i in data:
        k = i + ':'
        v = data[i]
        if (type(v) is dict):
            for entry in draw_app_tests(v):
                hdrs.append((k,list(entry)))
        else:
            hdrs.append((k, v))
    return hdrs



def results(state, flow):
    hdrs = draw_app_tests(flow.request.app_tests)
    txt = common.format_keyvals(hdrs,
      key_format='header')
    return searchable.Searchable(txt)
# okay decompiling tests.cpython-38.pyc
