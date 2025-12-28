#!/usr/bin/env python

""" Minimalistic standalone example """

import sys
from wsgiref.simple_server import make_server
from copr import application as app

CONFIG = 'copr-test.yaml'

def wrapper(env, sresp):
    """ wrapper for initializing environment """
    env['config'] = CONFIG
    return app(env, sresp)

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        CONFIG = sys.argv[1]
    with make_server(host='', port=8001, app=wrapper) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(' terminating...')
