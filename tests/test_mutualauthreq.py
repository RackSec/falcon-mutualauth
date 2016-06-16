from __future__ import absolute_import, division, print_function

import multiprocessing as mp
import os

import falcon
import falcon.testing as testing

import requests

from twisted.internet import reactor, ssl
from twisted.web.server import Site
from twisted.web.wsgi import WSGIResource

from falcon_mutualauth.mutualauth import Authorize, MutualAuthRequest


class HelloResource(object):
    def on_get(self, req, resp):
        resp.body = 'hello alice!'


class TestTLSCerts(testing.TestCase):
    def setUp(self):
        super(TestTLSCerts, self).setUp()

        tests_dir = os.path.dirname(__file__)
        self._certs_dir = os.path.join(
            tests_dir,
            'fixtures',
            'certs'
        )

        self._skeypath = self._cert_path('server-key.pem')
        self._scrtpath = self._cert_path('server-cert.pem')
        self._ccertpath = self._cert_path('ca-cert.pem')

        self._server_key = self._load_text_file(self._skeypath)
        self._server_crt = self._load_text_file(self._scrtpath)
        self._ca_cert = self._load_text_file(self._ccertpath)

        self._session = requests.Session()
        self._session.verify = self._cert_path('ca-cert.pem')
        self._session.cert = (self._cert_path('client-cert.pem'),
                              self._cert_path('client-key.pem'))

        self._server = mp.Process(target=self._server_run)
        self._server.start()

        self._server.join(0.2)

    def tearDown(self):
        self._server.terminate()

    def _load_text_file(self, filename):
        with open(filename, 'r') as infile:
            return infile.read()

    def _cert_path(self, filename):
        return os.path.join(self._certs_dir, filename)

    def _create(self):
        hellos = HelloResource()
        middleware = [Authorize('user')]
        api = falcon.API(middleware=middleware)

        api.add_route('/', hellos)

        return api

    def _create_tls_context(self, server_cert, server_key, ca_cert):
        """Create a twisted TLS context factory.

        :param server_cert: PEM-formatted server cert as a string.
        :param server_key: PEM-formatted private key as a string.
        :param ca_cert: PEM-formatted CA bundle as a string.
        """
        certificate = ssl.PrivateCertificate.loadPEM(server_cert +
                                                     '\n' + server_key)
        authority = ssl.Certificate.loadPEM(ca_cert)

        return certificate.options(authority)

    def _server_run(self):
        app = self._create()
        resource = WSGIResource(reactor, reactor.getThreadPool(), app)

        MutualAuthRequest.roles_map = {'Alice': ['user']}
        site = Site(resource, requestFactory=MutualAuthRequest)

        ctx = self._create_tls_context(self._server_crt,
                                       self._server_key,
                                       self._ca_cert)

        reactor.listenSSL(interface='localhost',
                          port=8080,
                          factory=site,
                          contextFactory=ctx)

        reactor.run()

    def test_authorized(self):
        resp = self._session.get('https://127.0.0.1:8080/')
        self.assertEqual(resp.status_code, 200)

    def test_unauthorized(self):
        cert = (self._cert_path('client-cert-eve.pem'),
                self._cert_path('client-key-eve.pem'))

        resp = self._session.get('https://127.0.0.1:8080/', cert=cert)
        self.assertEqual(resp.status_code, 403)

        headers = {'X-User-Roles': 'user'}
        resp = self._session.get('https://127.0.0.1:8080/', cert=cert,
                                 headers=headers)
        self.assertEqual(resp.status_code, 403)
