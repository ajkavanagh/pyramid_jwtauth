# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import print_function

import unittest
import json
import time
import datetime

from webtest import TestApp

from zope.interface.verify import verifyClass

from pyramid.request import Request
from pyramid.response import Response
from pyramid.config import Configurator
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.httpexceptions import HTTPForbidden, HTTPUnauthorized
from pyramid.security import (unauthenticated_userid,
                              authenticated_userid,
                              effective_principals,
                              Everyone,
                              Authenticated)

from pyramid_jwtauth import (JWTAuthenticationPolicy,
                             authenticate_request as jwt_authenticate_request)
import pyramid_jwtauth.utils

MASTER_SECRET = "V8 JUICE IS 1/8TH GASOLINE"


def make_request(config, path="/", environ={}):
    """Helper function for making pyramid Request objects."""
    my_environ = {}
    my_environ["wsgi.version"] = (1, 0)
    my_environ["wsgi.multithread"] = True
    my_environ["wsgi.multiprocess"] = True
    my_environ["wsgi.run_once"] = False
    my_environ["wsgi.url_scheme"] = "http"
    my_environ["REQUEST_METHOD"] = "GET"
    my_environ["SCRIPT_NAME"] = ""
    my_environ["PATH_INFO"] = path
    my_environ["SERVER_NAME"] = "localhost"
    my_environ["SERVER_PORT"] = "5000"
    my_environ["QUERY_STRING"] = "5000"
    my_environ.update(environ)
    request = Request(my_environ)
    request.registry = config.registry
    return request


# Something non-callable, to test loading non-callables by name.
stub_non_callable = None


def stub_find_groups(userid, request):
    """Groupfinder with the following rules:

        * any user with "bad" in their name is invalid
        * the "test" user belongs to group "group"
        * all other users have no groups

    """
    if "bad" in userid:
        return None
    if userid == "test":
        return ["group"]
    return []


def stub_view_public(request):
    """Stub view that returns userid if logged in, None otherwise."""
    userid = unauthenticated_userid(request)
    return Response(str(userid))


def stub_view_auth(request):
    """Stub view that returns userid if logged in, fails if not."""
    userid = authenticated_userid(request)
    if userid is None:
        raise HTTPForbidden
    return Response(userid)


def stub_view_groups(request):
    """Stub view that returns groups if logged in, fails if not."""
    groups = effective_principals(request)
    return Response(json.dumps([str(g) for g in groups]))

def stub_decode_mac_id(request, id, suffix="-SECRET"):
    """Stub mac-id-decoding function that appends suffix to give the secret."""
    return id, id + suffix


def stub_encode_mac_id(request, id, suffix="-SECRET"):
    """Stub mac-id-encoding function that appends suffix to give the secret."""
    return id, id + suffix

def make_claims(userid, claims=None):
    if claims is None:
        claims = {}
    if 'sub' not in claims:
        claims['sub'] = userid
    now = datetime.datetime.utcnow()
    if 'iat' not in claims:
        claims['iat'] = now
    if 'nbf' not in claims:
        claims['nbf'] = now
    if 'exp' not in claims:
        claims['exp'] = now + datetime.timedelta(seconds=10)
    return claims


class TestJWTAuthenticationPolicy(unittest.TestCase):
    """Testcases for the JWTAuthenticationPolicy class."""

    def setUp(self):
        self.config = Configurator(settings={
            "jwtauth.find_groups": "pyramid_jwtauth.tests.test_jwtauth:stub_find_groups",
            "jwtauth.master_secret": MASTER_SECRET,
        })
        self.config.include("pyramid_jwtauth")
        self.config.add_route("public", "/public")
        self.config.add_view(stub_view_public, route_name="public")
        self.config.add_route("auth", "/auth")
        self.config.add_view(stub_view_auth, route_name="auth")
        self.config.add_route("groups", "/groups")
        self.config.add_view(stub_view_groups, route_name="groups")
        self.app = TestApp(self.config.make_wsgi_app())
        self.policy = self.config.registry.queryUtility(IAuthenticationPolicy)

    def _make_request(self, *args, **kwds):
        return make_request(self.config, *args, **kwds)

    # create an authenticated request that has a JWT with the userid set
    # in our case, this is the 'sub' request.
    #
    # we need to have the following claims as a minimum:
    # 'sub': the userid that we want to authenticate - it can be anything.
    # 'iat': the issued at time stamp
    # 'nbf': the not before time stamp
    # 'exp': the expiry time for the JWT
    def _make_authenticated_request(self, userid, *args, **kwds):
        claims = None
        if 'claims' in kwds:
            claims = kwds['claims']
            del kwds['claims']
        req = self._make_request(*args, **kwds)
        # creds = self._get_credentials(req, userid=userid)
        claims = make_claims(userid=userid, claims=claims)
        # jwt_authenticate_request(req, **creds)
        # note jwt_authenticate_request() returns headers if wanted
        jwt_authenticate_request(req, claims, MASTER_SECRET)
        return req

    def test_the_class_implements_auth_policy_interface(self):
        verifyClass(IAuthenticationPolicy, JWTAuthenticationPolicy)

    def test_from_settings_can_explicitly_set_all_properties(self):
        policy = JWTAuthenticationPolicy.from_settings({
          "jwtauth.find_groups": "pyramid_jwtauth.tests.test_jwtauth:stub_find_groups",
          "jwtauth.master_secret": MASTER_SECRET,
          # "jwtauth.decode_mac_id": "pyramid_macauth.tests:stub_decode_mac_id",
          # "jwtauth.encode_mac_id": "pyramid_macauth.tests:stub_encode_mac_id",
        })
        self.assertEqual(policy.find_groups, stub_find_groups)
        self.assertEqual(policy.master_secret, MASTER_SECRET)
        # self.assertTrue(isinstance(policy.nonce_cache, macauthlib.NonceCache))
        # self.assertEqual(policy.decode_mac_id, stub_decode_mac_id)
        # self.assertEqual(policy.encode_mac_id, stub_encode_mac_id)

    # def test_from_settings_passes_on_args_to_nonce_cache(self):
    #     policy = MACAuthenticationPolicy.from_settings({
    #       "macauth.nonce_cache": "macauthlib:NonceCache",
    #       "macauth.nonce_cache_nonce_ttl": 42,
    #     })
    #     self.assertTrue(isinstance(policy.nonce_cache, macauthlib.NonceCache))
    #     self.assertEqual(policy.nonce_cache.nonce_ttl, 42)
    #     self.assertRaises(TypeError, MACAuthenticationPolicy.from_settings, {
    #       "macauth.nonce_cache": "macauthlib:NonceCache",
    #       "macauth.nonce_cache_invalid_arg": "WHAWHAWHAWHA",
    #     })

    def test_from_settings_errors_out_on_unexpected_keyword_args(self):
        self.assertRaises(ValueError, JWTAuthenticationPolicy.from_settings, {
          "jwtauth.unexpected": "spanish-inquisition",
        })

    # def test_from_settings_errors_out_on_args_to_a_non_callable(self):
    #     self.assertRaises(ValueError, MACAuthenticationPolicy.from_settings, {
    #       "macauth.nonce_cache": "pyramid_macauth.tests:stub_non_callable",
    #       "macauth.nonce_cache_arg": "invalidarg",
    #     })

    # def test_from_settings_errors_out_if_decode_mac_id_is_not_callable(self):
    #     self.assertRaises(ValueError, MACAuthenticationPolicy.from_settings, {
    #       "macauth.decode_mac_id": "pyramid_macauth.tests:stub_non_callable",
    #     })

    # def test_from_settings_errors_out_if_encode_mac_id_is_not_callable(self):
    #     self.assertRaises(ValueError, MACAuthenticationPolicy.from_settings, {
    #       "macauth.encode_mac_id": "pyramid_macauth.tests:stub_non_callable",
    #     })

    def test_from_settings_produces_sensible_defaults(self):
        policy = JWTAuthenticationPolicy.from_settings({})
        # Using __code__ here is a Py2/Py3 compatible way of checking
        # that a bound and unbound method point to the same function object.
        self.assertEqual(policy.find_groups.__code__,
                          JWTAuthenticationPolicy.find_groups.__code__)

    # def test_from_settings_curries_args_to_decode_mac_id(self):
    #     policy = MACAuthenticationPolicy.from_settings({
    #       "macauth.decode_mac_id": "pyramid_macauth.tests:stub_decode_mac_id",
    #       "macauth.decode_mac_id_suffix": "-TEST",
    #     })
    #     self.assertEqual(policy.decode_mac_id(None, "id"), ("id", "id-TEST"))

    # def test_from_settings_curries_args_to_encode_mac_id(self):
    #     policy = MACAuthenticationPolicy.from_settings({
    #       "macauth.encode_mac_id": "pyramid_macauth.tests:stub_encode_mac_id",
    #       "macauth.encode_mac_id_suffix": "-TEST",
    #     })
    #     self.assertEqual(policy.encode_mac_id(None, "id"), ("id", "id-TEST"))

    # not sure if this test is particularly useful as JWTAuthenticationPolicy
    # doesn't work on 'remembering' requests.
    def test_remember_does_nothing(self):
        policy = JWTAuthenticationPolicy()
        req = self._make_authenticated_request("test@moz.com", "/")
        self.assertEqual(policy.remember(req, "test@moz.com"), [])

    def test_forget_gives_a_challenge_header(self):
        policy = JWTAuthenticationPolicy()
        req = self._make_authenticated_request("test@moz.com", "/")
        headers = policy.forget(req)
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0][0], "WWW-Authenticate")
        self.assertTrue(headers[0][1] == "JWT")

    def test_forget_gives_a_challenge_header_with_custom_scheme(self):
        policy = JWTAuthenticationPolicy(scheme='Bearer')
        req = self._make_authenticated_request("test@moz.com", "/")
        headers = policy.forget(req)
        self.assertTrue(headers[0][1] == "Bearer")

    def test_unauthenticated_requests_get_a_challenge(self):
        r = self.app.get("/auth", status=401)
        challenge = r.headers["WWW-Authenticate"]
        self.assertTrue(challenge.startswith("JWT"))

    def test_unauthenticated_requests_get_a_challenge_custom_scheme(self):
        self.policy.scheme = 'Bearer'
        r = self.app.get("/auth", status=401)
        challenge = r.headers["WWW-Authenticate"]
        self.assertTrue(challenge.startswith('Bearer'))

    def test_authenticated_request_works(self):
        req = self._make_authenticated_request("test@moz.com", "/auth")
        r = self.app.request(req)
        self.assertEqual(r.body, b"test@moz.com")

    # def test_authentication_fails_when_macid_has_no_userid(self):
    #     req = self._make_request("/auth")
    #     creds = self._get_credentials(req, hello="world")
    #     macauthlib.sign_request(req, **creds)
    #     self.app.request(req, status=401)

    def test_authentication_with_non_jwt_scheme_fails(self):
        req = self._make_request("/auth")
        req.authorization = "OpenID hello=world"
        self.app.request(req, status=401)
        req = self._make_request("/public")
        req.authorization = "OpenID hello=world"
        self.app.request(req, status=200)

    # def test_authentication_without_macid_fails(self):
    #     req = self._make_signed_request("test@moz.com", "/auth")
    #     authz = req.environ["HTTP_AUTHORIZATION"]
    #     authz = authz.replace("id", "idd")
    #     req.environ["HTTP_AUTHORIZATION"] = authz
    #     self.app.request(req, status=401)

    # def test_authentication_without_timestamp_fails(self):
    #     req = self._make_signed_request("test@moz.com", "/auth")
    #     authz = req.environ["HTTP_AUTHORIZATION"]
    #     authz = authz.replace("ts", "typostamp")
    #     req.environ["HTTP_AUTHORIZATION"] = authz
    #     self.app.request(req, status=401)

    # def test_authentication_without_nonce_fails(self):
    #     req = self._make_signed_request("test@moz.com", "/auth")
    #     authz = req.environ["HTTP_AUTHORIZATION"]
    #     authz = authz.replace("nonce", "typonce")
    #     req.environ["HTTP_AUTHORIZATION"] = authz
    #     self.app.request(req, status=401)

    def test_authentication_with_expired_timestamp_fails(self):
        req = self._make_authenticated_request("test@moz.com",
                                               "/auth")
        self.app.request(req, status=200)
        # now do an out of date one.
        ts = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        claims = {'exp': ts}
        req = self._make_authenticated_request("test@moz.com",
                                               "/auth",
                                               claims=claims)
        self.app.request(req, status=401)

    def test_can_get_claims_from_token(self):
        claims = {
            'urn:websandhq.co.uk/auth:jti': 'hello'
        }
        req = self._make_authenticated_request("test@moz.com",
                                               "/auth",
                                               claims=claims)
        policy = JWTAuthenticationPolicy(
            master_secret="V8 JUICE IS 1/8TH GASOLINE")
        encoded_claims = policy.get_claims(req)
        self.assertTrue('urn:websandhq.co.uk/auth:jti' in encoded_claims)
        self.assertEqual(encoded_claims['urn:websandhq.co.uk/auth:jti'],
                          'hello')


    # def test_authentication_with_far_future_timestamp_fails(self):
    #     req = self._make_request("/auth")
    #     creds = self._get_credentials(req, username="test@moz.com")
    #     # Do an initial request so that the server can
    #     # calculate and cache our clock skew.
    #     ts = str(int(time.time()))
    #     req.authorization = ("MAC", {"ts": ts})
    #     macauthlib.sign_request(req, **creds)
    #     self.app.request(req, status=200)
    #     # Now do one with a far future timestamp.
    #     ts = str(int(time.time() + 1000))
    #     req.authorization = ("MAC", {"ts": ts})
    #     macauthlib.sign_request(req, **creds)
    #     self.app.request(req, status=401)

    # def test_authentication_with_reused_nonce_fails(self):
    #     req = self._make_request("/auth")
    #     creds = self._get_credentials(req, username="test@moz.com")
    #     # First request with that nonce should succeed.
    #     req.authorization = ("MAC", {"nonce": "PEPPER"})
    #     macauthlib.sign_request(req, **creds)
    #     r = self.app.request(req)
    #     self.assertEqual(r.body, b"test@moz.com")
    #     # Second request with that nonce should fail.
    #     req = self._make_request("/auth")
    #     req.authorization = ("MAC", {"nonce": "PEPPER"})
    #     macauthlib.sign_request(req, **creds)
    #     self.app.request(req, status=401)

    # def test_authentication_with_busted_macid_fails(self):
    #     req = self._make_signed_request("test@moz.com", "/auth")
    #     id = macauthlib.utils.parse_authz_header(req)["id"]
    #     authz = req.environ["HTTP_AUTHORIZATION"]
    #     authz = authz.replace(id, "XXX" + id)
    #     req.environ["HTTP_AUTHORIZATION"] = authz
    #     self.app.request(req, status=401)

    # def test_authentication_with_busted_signature_fails(self):
    #     req = self._make_request("/auth")
    #     creds = self._get_credentials(req, username="test@moz.com")
    #     macauthlib.sign_request(req, **creds)
    #     signature = macauthlib.utils.parse_authz_header(req)["mac"]
    #     authz = req.environ["HTTP_AUTHORIZATION"]
    #     authz = authz.replace(signature, "XXX" + signature)
    #     req.environ["HTTP_AUTHORIZATION"] = authz
    #     self.app.request(req, status=401)

    def test_groupfinder_can_block_authentication(self):
        req = self._make_authenticated_request("baduser", "/auth")
        r = self.app.request(req, status=403)
        req = self._make_authenticated_request("baduser", "/public")
        r = self.app.request(req, status=200)
        self.assertEqual(r.body, b"baduser")

    def test_groupfinder_groups_are_correctly_reported(self):
        req = self._make_request("/groups")
        r = self.app.request(req)
        self.assertEqual(r.json,
                          [str(Everyone)])
        req = self._make_authenticated_request("gooduser", "/groups")
        r = self.app.request(req)
        self.assertEqual(r.json,
                          ["gooduser", str(Everyone), str(Authenticated)])
        req = self._make_authenticated_request("test", "/groups")
        r = self.app.request(req)
        self.assertEqual(r.json,
                          ["test", str(Everyone), str(Authenticated), "group"])
        req = self._make_authenticated_request("baduser", "/groups")
        r = self.app.request(req)
        self.assertEqual(r.json,
                          [str(Everyone)])

    def test_access_to_public_urls(self):
        # Request with no credentials is allowed access.
        req = self._make_request("/public")
        resp = self.app.request(req)
        self.assertEqual(resp.body, b"None")
        # Request with valid credentials is allowed access.
        req = self._make_authenticated_request("test@moz.com", "/public")
        resp = self.app.request(req)
        self.assertEqual(resp.body, b"test@moz.com")
        # Request with invalid credentials still reports a userid.
        req = self._make_authenticated_request("test@moz.com", "/public")
        token = pyramid_jwtauth.utils.parse_authz_header(req)["token"]
        bits = token.split('.')
        bits[2] = 'XXX' + bits[2]
        broken_token = '.'.join(bits)
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(token, broken_token)
        req.environ["HTTP_AUTHORIZATION"] = authz
        resp = self.app.request(req)
        self.assertEqual(resp.body, b"test@moz.com")
        # Request with malformed credentials gets a 401
        # req = self._make_signed_request("test@moz.com", "/public")
        # tokenid = macauthlib.utils.parse_authz_header(req)["id"]
        # authz = req.environ["HTTP_AUTHORIZATION"]
        # authz = authz.replace(tokenid, "XXX" + tokenid)
        # req.environ["HTTP_AUTHORIZATION"] = authz
        # resp = self.app.request(req, status=401)

    # def test_check_signature_fails_if_no_params_present(self):
    #     req = self._make_request("/auth")
    #     self.assertRaises(HTTPUnauthorized,
    #                       self.policy._check_signature, req, "XXX")

    def test_default_groupfinder_returns_empty_list(self):
        policy = JWTAuthenticationPolicy()
        req = self._make_request("/auth")
        self.assertEqual(policy.find_groups("test", req), [])

    def test_auth_can_be_checked_several_times_on_same_request(self):
        req = self._make_authenticated_request("test@moz.com", "/public")
        self.assertEqual(authenticated_userid(req), "test@moz.com")
        self.assertEqual(authenticated_userid(req), "test@moz.com")


class TestJWTAuthenticationPolicy_with_RSA(unittest.TestCase):
    """Testcases for the JWTAuthenticationPolicy class."""

    def setUp(self):
        self.config = Configurator(settings={
          "jwtauth.private_key_file": 'pyramid_jwtauth/tests/testkey',
          "jwtauth.public_key_file": 'pyramid_jwtauth/tests/testkey.pub',
          "jwtauth.algorithm": "RS256",
        })
        self.config.include("pyramid_jwtauth")
        self.config.add_route("public", "/public")
        self.config.add_view(stub_view_public, route_name="public")
        self.config.add_route("auth", "/auth")
        self.config.add_view(stub_view_auth, route_name="auth")
        self.config.add_route("groups", "/groups")
        self.config.add_view(stub_view_groups, route_name="groups")
        self.app = TestApp(self.config.make_wsgi_app())
        self.policy = self.config.registry.queryUtility(IAuthenticationPolicy)

    def _make_request(self, *args, **kwds):
        return make_request(self.config, *args, **kwds)

    def test_from_settings_with_RSA_public_private_key(self):
        self.assertEqual(self.policy.algorithm, 'RS256')
        self.assertEqual(self.policy.master_secret, None)
        # from Crypto.PublicKey import RSA
        with open('pyramid_jwtauth/tests/testkey', 'r') as rsa_priv_file:
            private_key = rsa_priv_file.read()
            self.assertEqual(self.policy.private_key, private_key)
        with open('pyramid_jwtauth/tests/testkey.pub', 'r') as rsa_pub_file:
            public_key = rsa_pub_file.read()
            self. assertEqual(self.policy.public_key, public_key)

        self.assertNotEqual(private_key, public_key)
        req = self._make_request("/auth")
        claims = make_claims(userid="test@moz.com")
        jwt_authenticate_request(req, claims, private_key, 'RS256')

        token = pyramid_jwtauth.utils.parse_authz_header(req)["token"]
        userid = self.policy.authenticated_userid(req)
        self.assertEqual(userid, "test@moz.com")

        import jwt
        payload = jwt.decode(token, key=public_key, verify=True)
        self.assertIn('sub', payload)
        self.assertEqual(payload['sub'], "test@moz.com")

        r = self.app.request(req)
        self.assertEqual(r.body, b"test@moz.com")


class TestJWTAuthenticationPolicyJWTOptions(unittest.TestCase):

    def _make_request(self, *args, **kwds):
        return make_request(self.config, *args, **kwds)

    def setup_helper(self, config_settings):
        self.config = Configurator(settings=config_settings)
        self.config.include("pyramid_jwtauth")
        # self.config.add_route("public", "/public")
        # self.config.add_view(stub_view_public, route_name="public")
        # self.config.add_route("auth", "/auth")
        # self.config.add_view(stub_view_auth, route_name="auth")
        # self.config.add_route("groups", "/groups")
        # self.config.add_view(stub_view_groups, route_name="groups")
        self.app = TestApp(self.config.make_wsgi_app())
        self.policy = self.config.registry.queryUtility(IAuthenticationPolicy)


    def test_decode_fails_no_override_on_aud_claim(self):
        self.setup_helper({
            "jwtauth.find_groups": "pyramid_jwtauth.tests.test_jwtauth:stub_find_groups",
            "jwtauth.master_secret": MASTER_SECRET,})
        # make a token with an audience claim
        claims = make_claims('user1', claims={'aud': 'me'})
        req = self._make_request("/auth")
        jwt_authenticate_request(req, claims, MASTER_SECRET)
        token = pyramid_jwtauth.utils.parse_authz_header(req)["token"]
        from jwt.exceptions import InvalidAudienceError
        with self.assertRaises(InvalidAudienceError):
            userid = self.policy.authenticated_userid(req)
        # self.assertEqual(userid, "test@moz.com")

    def test_decode_passes_with_override_on_aud_claim(self):
        self.setup_helper({
            "jwtauth.find_groups": "pyramid_jwtauth.tests.test_jwtauth:stub_find_groups",
            "jwtauth.master_secret": MASTER_SECRET,
            "jwtauth.disable_verify_aud": True,})
        # make a token with an audience claim
        claims = make_claims('user1', claims={'aud': 'me'})
        req = self._make_request("/auth")
        jwt_authenticate_request(req, claims, MASTER_SECRET)
        token = pyramid_jwtauth.utils.parse_authz_header(req)["token"]
        userid = self.policy.authenticated_userid(req)
        self.assertEqual(userid, "user1")
