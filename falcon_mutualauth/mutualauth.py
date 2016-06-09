# Copyright (c) 2016 Rackspace
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import falcon
import structlog

from twisted.web.server import Request


logger = structlog.get_logger()


class MutualAuthRequest(Request):

    """HTTP request received over mutually-authenticated TLS.

    This class overrides the default request processing to inject additional
    headers into the request based on the peer cert. These headers will
    override any headers of the same name, if passed by the client, to
    protect against spoofing.

    These headers include::

        X-User-Roles: A comma-delimited list of roles mapped to the user. The
            user is specified by the peer cert's CN.
    """

    roles_map = {}

    def _inject_headers(self):
        peer_cert = self.channel.transport.getPeerCertificate()
        common_name = peer_cert.get_subject().CN

        roles = self.roles_map.get(common_name, [])
        self.requestHeaders.setRawHeaders(b'X-User-Roles', roles)

    def render(self, resource):
        # NOTE(kgriffs): Override render, instead of process, to ensure
        #   that we have the last say in the value of the headers.
        self._inject_headers()
        super(MutualAuthRequest, self).render(resource)


class Authorize(object):

    """Authorize the request.

    A user is authorized to access a given resource based on the value
    of the X-User-Roles header. Each resource class may specify the
    roles that are allowed to access that resource by setting an
    `authorized_for` class variable to a set of role names. If the
    class variable is missing, the default roles will be used.

    :param *default_roles: One or more roles that are allowed to access the
        resource unless overridden by setting an `authorized_for`
        class variable on a resource.
    """

    def __init__(self, *default_roles):
        self._default_roles = set(default_roles)

    # NOTE(fxfitz): Falcon v1.0 requires the params parameter, so adding this
    # here now to be forward compatible with Falcon when v1.0 is released
    def process_resource(self, req, resp, resource, params=None):
        authorized_roles = getattr(
            resource, 'authorized_for', self._default_roles)
        roles = set(req.get_header('X-User-Roles').split(','))

        if roles.isdisjoint(authorized_roles):
            msg = 'You are not authorized to access this resource.'

            # TODO(fxfitz): Request IP is currently returning the HA Proxy
            # IP address; we should log the original client's/requester's IP
            logger.info("access.denied",
                        message="Header role is not an authorized role.",
                        header_roles=req.get_header('X-User-Roles'),
                        user_agent=req.user_agent,
                        request_ip=req.env['REMOTE_ADDR'])
            raise falcon.HTTPForbidden('Access Denied', msg)
