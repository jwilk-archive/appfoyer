# Copyright © 2015-2017 Jakub Wilk <jwilk@jwilk.net>
# SPDX-License-Identifier: MIT

'''
color terminal support
'''

import builtins
import re

class _seq:
    red = '\x1B[31m'
    green = '\x1B[32m'
    yellow = '\x1B[33m'
    cyan = '\x1B[36m'
    bold = '\x1B[1m'
    dim = '\x1B[1;30m'
    off = '\x1B[0m'
    reverse = '\x1B[7m'
    unreverse = '\x1B[27m'

def _quote_unsafe_char(ch):
    if ch == '\t':
        return '{t.reverse}\t{t.unreverse}'.format(t=_seq)
    elif ch < ' ' or ch == '\x7F':
        return '{t.reverse}^{c}{t.unreverse}'.format(t=_seq, c=chr(ord('@') ^ ord(ch)))
    else:
        return '{t.reverse}<U+{u:04X}>{t.unreverse}'.format(t=_seq, u=ord(ch))

def _quote_unsafe(s):
    return ''.join(map(_quote_unsafe_char, s))

def _quote(s):
    if not isinstance(s, str):
        return s
    chunks = re.split(r'([\x00-\x1F\x7F-\x9F]+)', s)
    def esc():
        for i, s in enumerate(chunks):
            if i & 1:
                yield _quote_unsafe(s)
            else:
                yield s
    return ''.join(esc())

def format(_s, **kwargs):
    kwargs.update(t=_seq)
    return _s.format(**{
        key: _quote(value)
        for key, value in kwargs.items()
    })

def print(_s='', **kwargs):
    builtins.print(format(_s, **kwargs))

__all__ = [
    'format',
    'print',
]

# vim:ts=4 sts=4 sw=4 et
