# Copyright © 2016-2020 Jakub Wilk <jwilk@jwilk.net>
# SPDX-License-Identifier: MIT

'''
command-line interface
'''

import argparse
import io
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request

import lib.colors
import lib.pager

user_agent = 'appfoyer (https://github.com/jwilk/appfoyer)'

def get(url, headers=()):
    headers = dict(headers)
    headers.update(
        {'User-Agent': user_agent}
    )
    request = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(request)

def get_json(url, headers=()):
    headers = dict(headers)
    headers.update(
        {'Content-Type': 'application/json'}
    )
    with get(url, headers) as fp:
        with io.TextIOWrapper(fp, encoding='UTF-8') as tfp:
            return json.load(tfp)

_dispatch = []

def dispatch(regex):
    def decorator(cmd):
        _dispatch.append((regex, cmd))
        return cmd
    return decorator

def get_git_url():
    try:
        url = subprocess.check_output('git ls-remote --get-url'.split())
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 128:
            return
        raise
    url = url.decode('ASCII').rstrip()
    (scheme, netloc, path, query, fragment) = urllib.parse.urlsplit(url)
    if netloc == 'github.com':
        if path.endswith('.git'):
            path = path[:-4]
        path = path.lstrip('/')
        return path
    else:
        return

def main():
    if sys.version_info < (3, 4, 3):
        raise RuntimeError('Python >= 3.4.3 is required')
    ap = argparse.ArgumentParser()
    ap.add_argument('url', metavar='URL')
    options = ap.parse_args()
    if options.url == '.':
        options.url = get_git_url()
    url = urllib.parse.urljoin('https://ci.appveyor.com/project/', options.url)
    (scheme, netloc, path, query, fragment) = urllib.parse.urlsplit(url)
    if scheme not in {'http', 'https'}:
        ap.error('unsupported URL')
    if netloc != 'ci.appveyor.com':
        ap.error('unsupported URL')
    for regex, cmd in _dispatch:
        regex = ('/' if regex else '') + regex
        regex = r'\A/project/(?P<project>[\w.-]+/[\w.-]+){re}\Z'.format(re=regex)
        match = re.match(regex, path)
        if match is not None:
            break
    else:
        ap.error('unsupported URL')
    lib.colors.init()
    with lib.pager.autopager():
        return cmd(options, **match.groupdict())

@dispatch('')
@dispatch('history')
def show_history(options, project):
    url = 'https://ci.appveyor.com/api/projects/{project}/history?recordsNumber=10'
    url = url.format(project=project)
    data = get_json(url)
    for build in data['builds']:
        template = '{version} {branch} {status}'
        curious = False
        if build.get('finished') is None:
            template = '{t.yellow}' + template
        elif build['status'] != 'success':
            template = '{t.bold}{t.red}' + template
            curious = True
        lib.colors.print(template,
            version=build['version'],
            branch=build['branch'],
            status=build['status'],
        )
        url = 'https://ci.appveyor.com/project/{project}/build/{version}'
        url = url.format(project=project, version=build['version'])
        template = '{t.cyan}'
        if curious:
            template += '{t.bold}'
        template += '{url}{t.off}'
        lib.colors.print(template, url=url, space='')
        print()

@dispatch(r'build/(?P<version>[^/\s]+)')
def show_build(options, project, version):
    url = 'https://ci.appveyor.com/api/projects/{project}/build/{version}'
    url = url.format(project=project, version=version)
    data = get_json(url)
    data = data['build']['jobs']
    for job in data:
        template = '{version} {name}'
        error = False
        if job.get('finished') is None:
            template = '{t.yellow}' + template
        elif job['status'] != 'success':
            error = True
            template = '{t.bold}{t.red}' + template
        template += '{t.off}'
        lib.colors.print(template, version=version, name=job['name'])
        url = 'https://ci.appveyor.com/project/{project}/build/{version}/job/{id}'
        url = url.format(project=project, version=version, id=job['jobId'])
        template = '{t.cyan}'
        if error:
            template += '{t.bold}'
        template += '{url}{t.off}'
        lib.colors.print(template, url=url, space='')
        print()

@dispatch(r'builds/(?P<build_id>\d+)')
def show_build_by_id(options, project, build_id):
    url = 'https://ci.appveyor.com/api/projects/{project}/builds/{id}'
    url = url.format(project=project, id=build_id)
    data = get_json(url)
    data = data['build']['jobs']
    for job in data:
        template = '{name}'
        error = False
        if job.get('finished') is None:
            template = '{t.yellow}' + template
        elif job['status'] != 'success':
            error = True
            template = '{t.bold}{t.red}' + template
        template += '{t.off}'
        lib.colors.print(template, name=job['name'])
        url = 'https://ci.appveyor.com/project/{project}/builds/{build_id}/job/{job_id}'
        url = url.format(project=project, build_id=build_id, job_id=job['jobId'])
        template = '{t.cyan}'
        if error:
            template += '{t.bold}'
        template += '{url}{t.off}'
        lib.colors.print(template, url=url, space='')
        print()

@dispatch(r'builds?/[^/\s]+/job/(?P<job_id>\w+)')
def show_job(options, project, job_id):
    url = 'https://ci.appveyor.com/api/buildjobs/{id}/console'.format(id=job_id)
    url = url.format(id=job_id)
    with get(url) as fp:
        with io.TextIOWrapper(fp, encoding='UTF-8') as tfp:
            data = tfp.read()
    data = '[' + data[:-1] + ']'
    data = json.loads(data)
    template = '{t.dim}{time:8}{t.off} {text}'
    last_ts = ''
    text = ''
    for item in data:
        chunks = item['t']
        chunks = chunks.replace('\r\n', '\n')
        chunks = chunks.splitlines(keepends=True)
        for chunk in chunks:
            if chunk[-1] == '\n':
                text += chunk[:-1]
                ts = item['dt']
                if ts == last_ts:
                    ts = ''
                lib.colors.print(template, time=ts, text=text)
                last_ts = item['dt']
                text = ''
            else:
                text += chunk
    if text:
        ts = item['dt']
        if ts == last_ts:
            ts = ''
        lib.colors.print(template, time=ts, text=chunk)

__all__ = ['main']

# vim:ts=4 sts=4 sw=4 et
