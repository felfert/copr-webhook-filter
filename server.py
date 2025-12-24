#!/usr/bin/env python

""" Minimalistic standalone example """

from wsgiref.simple_server import make_server
from copr import application as app

def wrapper(env, sresp):
    """ wrapper for initializing environment """
    env['config'] = 'copr-test.yaml'
    return app(env, sresp)

if __name__ == '__main__':
    with make_server(host='', port=8001, app=wrapper) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(' terminating...')
