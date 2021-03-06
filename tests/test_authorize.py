import unittest

import falcon

import pytest

from falcon_mutualauth.mutualauth import Authorize


class FakeRequest(object):

    def __init__(self, role):
        self._role = role
        self.env = {'REMOTE_ADDR': 'http://test.test'}
        self.method = 'GET'
        self.user_agent = 'pytest'

    def get_header(self, header):
        assert header == 'X-User-Roles'
        return self._role


class FakeResource(object):

    def __init__(self, authorized_for_map):
        self.authorized_for_map = authorized_for_map


class TestAuthorize(unittest.TestCase):

    def setUp(self):
        self._auth = Authorize('admin', 'principal')
        self._resource = self._create_fake_resource()

    def _create_fake_resource(self):
        return None

    def test_log_in_as_admin(self):
        self._auth.process_resource(FakeRequest('admin'), None, self._resource)

    def test_log_in_as_principal(self):
        self._auth.process_resource(
            FakeRequest('principal'), None, self._resource)

    def test_log_in_as_principal_or_admin(self):
        self._auth.process_resource(
            FakeRequest('principal, admin'), None, self._resource)

    def test_should_fail_if_list_not_properly_formatted(self):
        with pytest.raises(falcon.HTTPForbidden):
            self._auth.process_resource(
                FakeRequest(' principal, admin'), None, self._resource)

    def test_should_fail_if_not_in_list(self):
        with pytest.raises(falcon.HTTPForbidden):
            self._auth.process_resource(
                FakeRequest('teacher'), None, self._resource)


class TestAuthorizeWithResource(TestAuthorize):

    def _create_fake_resource(self):
        authmap = {'on_get': ['admin', 'principal', 'superintendent']}
        return FakeResource(authmap)

    def test_log_in_as_superintendent(self):
        self._auth.process_resource(
            FakeRequest('superintendent'), None, self._resource)
