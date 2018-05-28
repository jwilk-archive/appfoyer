# Copyright © 2015-2018 Jakub Wilk <jwilk@jwilk.net>
# SPDX-License-Identifier: MIT

'''
automatic pager
'''

import contextlib
import io
import os
import shutil
import subprocess as ipc
import sys

def _find_command(command):
    if shutil.which(command):
        return command

def get_default_pager():
    # Use "pager" if it exist:
    # https://www.debian.org/doc/debian-policy/#document-ch-customized-programs
    # Fall back to "more", which is in POSIX.
    return (
        _find_command('pager')
        or 'more'
    )

@contextlib.contextmanager
def autopager():
    if os.name == 'nt':
        yield
        return
    if not sys.stdout.isatty():
        yield
        return
    cmdline = os.environ.get('PAGER') or get_default_pager()
    if cmdline == 'cat':
        yield
        return
    env = None
    if 'LESS' not in os.environ:
        env = dict(env or os.environ, LESS='FXR')
    if 'LV' not in os.environ:
        env = dict(env or os.environ, LV='-c')
    orig_stdout = sys.stdout
    try:
        pager = ipc.Popen(cmdline, shell=True, stdin=ipc.PIPE, env=env)
        try:
            sys.stdout = io.TextIOWrapper(pager.stdin,
                encoding=orig_stdout.encoding,
            )
            try:
                yield
            finally:
                sys.stdout.close()
        finally:
            pager.wait()
    except BrokenPipeError:
        sys.exit(1)
    finally:
        sys.stdout = orig_stdout

__all__ = [
    'autopager',
]

# vim:ts=4 sts=4 sw=4 et
