# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

A Pyramid authentication plugin for JSON Web Tokens:

    http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html

"""

from __future__ import absolute_import

__ver_major__ = 0
__ver_minor__ = 0
__ver_patch__ = 1
__ver_sub__ = ".dev2"
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__

import sys
import functools

from datetime import datetime
from calendar import timegm

from zope.interface import implementer

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.util import DottedNameResolver

import jwt

from .utils import parse_authz_header, normalize_request_object


@implementer(IAuthenticationPolicy)
class JWTAuthenticationPolicy(object):
    """Pyramid Authentication Policy implementing JWT Access Auth.

    This class provides an IAuthenticationPolicy implementation based on
    signed requests, using the JSON Web Token Authentication standard.

    The plugin can be customized with the following arguments:

        * find_groups:  a callable taking a userid and a Request object, and
                        returning a list of the groups that userid is a
                        member of.

        * master_secret:  a secret known only by the server, used for signing
                          JWT auth tokens in the default implementation.
                          This can also be an Cypto.PublicKey.RSA key.

        * leeway:  The default leeway (as a datetime.timedelta). Defaults to
                   None

        * userid_in_claim: The claim that the userid can be found in.  Normally
                           this is the 'sub' claim of the JWT, but this can
                           be overridden here.  This is used in
                           authenticated_userid() and related functions.
    """

    # The default value of master_secret is None, which will cause the library
    # to generate a fresh secret at application startup.
    master_secret = None

    def __init__(self, find_groups=None, master_secret=None, leeway=None,
                 userid_in_claim=None):
        if find_groups is not None:
            self.find_groups = find_groups
        if master_secret is not None:
            self.master_secret = master_secret
        if leeway is not None:
            self.leeway = leeway
        else:
            self.leeway = 0
        if userid_in_claim is not None:
            self.userid_in_claim = userid_in_claim
        else:
            self.userid_in_claim = 'sub'

    @classmethod
    def from_settings(cls, settings={}, prefix="jwtauth.", **extra):
        """Construct a JWTAuthenticationPolicy from deployment settings.

        This is a helper function for loading a JWTAuthenticationPolicy from
        settings provided in the pyramid application registry.  It extracts
        settings with the given prefix, converts them to the appropriate type
        and passes them into the constructor.
        """
        # Grab out all the settings keys that start with our prefix.
        jwtauth_settings = {}
        for name in settings:
            if not name.startswith(prefix):
                continue
            jwtauth_settings[name[len(prefix):]] = settings[name]
        # Update with any additional keyword arguments.
        jwtauth_settings.update(extra)
        # Pull out the expected keyword arguments.
        kwds = cls._parse_settings(jwtauth_settings)
        # Error out if there are unknown settings.
        for unknown_setting in jwtauth_settings:
            raise ValueError("unknown jwtauth setting: %s" % unknown_setting)
        # And finally we can finally create the object.
        return cls(**kwds)

    @classmethod
    def _parse_settings(cls, settings):
        """Parse settings for an instance of this class.

        This classmethod takes a dict of string settings and parses them into
        a dict of properly-typed keyword arguments, suitable for passing to
        the default constructor of this class.

        Implementations should remove each setting from the dict as it is
        processesed, so that any unsupported settings can be detected by the
        calling code.
        """
        load_function = _load_function_from_settings
        # load_object = _load_object_from_settings
        kwds = {}
        kwds["find_groups"] = load_function("find_groups", settings)
        kwds["master_secret"] = settings.pop("master_secret", None)
        kwds["leeway"] = settings.pop("leeway", 0)
        kwds["userid_in_claim"] = settings.pop("userid_in_claim", "sub")
        return kwds

    def authenticated_userid(self, request):
        """Get the authenticated userid for the given request.

        This method extracts the claimed userid from the request, checks
        the request signature in _get_credentials(), and calls the groupfinder
        callback to check the validity of the claimed identity.
        """
        userid = self._get_credentials(request)
        if userid is None:
            return None
        self._check_signature(request)
        if self.find_groups(userid, request) is None:
            return None
        return userid

    def unauthenticated_userid(self, request):
        """Get the unauthenticated userid for the given request.

        This method extracts the claimed userid from the request without
        checking its authenticity.  This means that the request signature
        is *not* checked when you call this method.  The groupfinder
        callback is also not called.
        """
        userid = self._get_credentials(request)
        return userid

    def effective_principals(self, request):
        """Get the list of effective principals for the given request.

        This method combines the authenticated userid from the request with
        with the list of groups returned by the groupfinder callback, if any.
        """
        principals = [Everyone]
        userid = self._get_credentials(request)
        if userid is None:
            return principals
        self._check_signature(request)
        groups = self.find_groups(userid, request)
        if groups is None:
            return principals
        principals.insert(0, userid)
        principals.append(Authenticated)
        principals.extend(groups)
        return principals

    def remember(self, request, principal, **kw):
        """Get headers to remember to given principal identity.

        This is a no-op for this plugin; the client is supposed to remember
        its MAC credentials and use them for all requests.
        """
        return []

    def forget(self, request):
        """Get headers to forget the identity in the given request.

        This simply issues a new WWW-Authenticate challenge, which should
        cause the client to forget any previously-provisioned credentials.
        """
        return [("WWW-Authenticate", "JWT")]

    def challenge(self, request, content="Unauthorized"):
        """Challenge the user for credentials.

        This method returns a 401 response using the WWW-Authenticate field
        as constructed by forget().  You might like to use it as pyramid's
        "forbidden view" when using this auth policy.
        """
        return HTTPUnauthorized(content, headers=self.forget(request))

    def find_groups(self, userid, request):
        """Find the list of groups for the given userid.

        This method provides a default implementation of the "groupfinder
        callback" used by many pyramid authn policies to look up additional
        user data.  It can be overridden by passing a callable into the
        JWTAuthenticationPolicy constructor.

        The default implementation returns an empty list.
        """
        return []

    def decode_jwt(self, request, jwtauth_token, leeway=None, verify=True):
        """Decode a JWTAuth token into its claims.

        This method deocdes the given JWT to provide the claims.  The JWT can
        fail if the token has expired (with appropriate leeway) or if the
        token won't validate due to the secret (key) being wrong.

        If the JWT doesn't verify then a number of Exceptions can be raised:
            DecodeError() - if the algorithm in the token isn't supported.
            DecodeError() - if the secret doesn't match (key, etc.)
            ExpiredSignature() - if the 'exp' claim has expired.
        """
        if leeway is None:
            leeway = self.leeway
        # print(type(self.master_secret), self.master_secret)
        claims = jwt.decode(jwtauth_token,
                            key=self.master_secret,
                            leeway=leeway,
                            verify=verify)
        return claims

    def encode_jwt(self, request, claims, key=None, algorithm='HS256'):
        """Encode a set of claims into a JWT token.

        This is just a proxy for jwt.encode() but uses the default
        master_secret that may have been set in configuring the library.
        """
        if key is None:
            key = self.master_secret
        # fix for older version of PyJWT which doesn't covert all of the time
        # claims.  This won't be needed in the future.
        encode_claims = _maybe_encode_time_claims(claims)

        jwtauth_token = jwt.encode(encode_claims, key=key, algorithm=algorithm)
        return jwtauth_token

    def _get_params(self, request):
        """Get the JWTAuth parameters from the given request.

        This method parses the Authorization header to get the JSON Web
        Token. If they seem sensible, we cache them in the request
        to avoid reparsing and return them as a dict.

        If the request contains no JWT Auth credentials, None is returned.
        """
        try:
            return request.environ["jwtauth.params"]
        except KeyError:
            params = parse_authz_header(request, None)
            if params is not None:
                if params.get("scheme").upper() != "JWT":
                    params = None
            request.environ["jwtauth.params"] = params
            return params

    def _get_credentials(self, request):
        """Extract the JWTAuth claims from the request.

        This method extracts and returns the claimed userid from the MACAuth
        data in the request, along with the corresonding request signing
        key.  It does *not* check the signature on the request.

        If there are no MACAuth credentials in the request then None
        is returned.  If the MACAuth token id is invalid then HTTPUnauthorized
        will be raised.
        """
        userid = request.environ.get("jwtauth.userid", False)
        if userid:
            return userid

        params = self._get_params(request)
        if params is None:
            return None
        if 'token' not in params:
            return None
        # Now try to pull out the claims from the JWT - note it is unusable if
        # we get a decode error, but might be okay if we get a signature error
        # Thus we may have to call decode TWICE, once with verify=True to see
        # if we just get a jwt.ExpiredSignature or jwt.DecodeError and if so,
        # the second time with verify=False to try to get the claims (i.e. to
        # ignore the jwt.ExpiredSignature)  we store whether the signature is
        # okay in jwtauth.signature_is_valid environ on the request
        def _get_claims():
            try:
                claims = self.decode_jwt(request, params['token'], verify=True)
                return claims, True
            except (jwt.DecodeError, jwt.ExpiredSignature):
                # try again with no verify
                try:
                    claims = self.decode_jwt(
                        request, params['token'], verify=False)
                    return claims, False
                except jwt.DecodeError:
                    # can't do anything with this.
                    return None, False

        claims, verify_okay = _get_claims()
        if claims is None:
            return None
        # so we don't have to check it again.
        request.environ["jwtauth.claims"] = claims
        request.environ["jwtauth.signature_is_valid"] = verify_okay
        # Now extract the userid
        if self.userid_in_claim in claims:
            request.environ["jwtauth.userid"] = claims[self.userid_in_claim]
            return claims[self.userid_in_claim]
        return None

    def get_claims(self, request):
        """Get the claims from the request - if they exist.

        Fetch the claims out of the token on the request, if it exists and is
        decodable.  Returns None if there are none or it couldn't be docoded.
        """
        userid = self._get_credentials(request)
        if userid is None:
            return None
        return request.environ.get("jwtauth.claims", None)

    def _check_signature(self, request):
        """See if the signature was valid

        It was already checked in _get_credentials() - this function just
        sees if it was valid.

        """
        # See if we've already checked the signature on this request.
        # This is important because pyramid doesn't cache the results
        # of authenticating the request, but we mark the nonce as stale
        # after the first check.
        if request.environ.get("jwtauth.signature_is_valid", False):
            return True
        # Grab the (hopefully cached) params from the request.
        params = self._get_params(request)
        if params is None:
            msg = "missing JWT token"
            raise self.challenge(request, msg)
        # We know the JWT auth token's signature isn't valid:
        msg = "invalid JWT signature"
        raise self.challenge(request, msg)


def _maybe_encode_time_claims(claims):
    encode_claims = claims.copy()
    # convert datetime to a intDate value in known time-format claims
    for time_claim in ['exp', 'iat', 'nbf']:
        if isinstance(encode_claims.get(time_claim), datetime):
            encode_claims[time_claim] = (
                timegm(encode_claims[time_claim].utctimetuple()))
    return encode_claims


@normalize_request_object
def authenticate_request(request, claims, key, algorithm='HS256'):
    """Authenticate a webob style request with the appropriate JWT token

    This creates the auth token using the claims and the key to ensure that
    will be accepted by this library.  Obviously, normally, a client would be
    making the request - so this is just useful as a 'canonical' way of
    creating a Authorization header
    """
    claims = _maybe_encode_time_claims(claims)
    jwtauth_token = jwt.encode(claims, key=key, algorithm=algorithm)
    if sys.version_info >= (3, 0, 0):
        jwtauth_token = jwtauth_token.decode(encoding='UTF-8')
    params = dict()
    params['token'] = jwtauth_token
    # Serialize the parameters back into the authz header, and return it.
    # WebOb has logic to do this that's not perfect, but good enough for us.
    request.authorization = ('JWT', params)
    return request.headers['Authorization']


def _load_function_from_settings(name, settings):
    """Load a plugin argument as a function created from the given settings.

    This function is a helper to load and possibly curry a callable argument
    to the plugin.  It grabs the value from the dotted python name found in
    settings[name] and checks that it is a callable.  It then looks for args
    of the form settings[name_*] and curries them into the function as extra
    keyword argument before returning.
    """
    # See if we actually have the named object.
    dotted_name = settings.pop(name, None)
    if dotted_name is None:
        return None
    func = DottedNameResolver(None).resolve(dotted_name)
    # Check that it's a callable.
    if not callable(func):
        raise ValueError("Argument %r must be callable" % (name,))
    # Curry in any keyword arguments.
    func_kwds = {}
    prefix = name + "_"
    for key in list(settings.keys()):
        if key.startswith(prefix):
            func_kwds[key[len(prefix):]] = settings.pop(key)
    # Return the original function if not currying anything.
    # This is both more efficent and better for unit testing.
    if func_kwds:
        func = functools.partial(func, **func_kwds)
    return func


def _load_object_from_settings(name, settings):
    """Load a plugin argument as an object created from the given settings.

    This function is a helper to load and possibly instanciate an argument
    to the plugin.  It grabs the value from the dotted python name found in
    settings[name].  If this is a callable, it looks for arguments of the
    form settings[name_*] and calls it with them to instanciate an object.
    """
    # See if we actually have the named object.
    dotted_name = settings.pop(name, None)
    if dotted_name is None:
        return None
    obj = DottedNameResolver(None).resolve(dotted_name)
    # Extract any arguments for the callable.
    obj_kwds = {}
    prefix = name + "_"
    for key in list(settings.keys()):
        if key.startswith(prefix):
            obj_kwds[key[len(prefix):]] = settings.pop(key)
    # Call it if callable.
    if callable(obj):
        obj = obj(**obj_kwds)
    elif obj_kwds:
        raise ValueError("arguments provided for non-callable %r" % (name,))
    return obj


def includeme(config):
    """Install JWTAuthenticationPolicy into the provided configurator.

    This function provides an easy way to install JWT Access Authentication
    into your pyramid application.  Loads a JWTAuthenticationPolicy from the
    deployment settings and installs it into the configurator.
    """
    # Hook up a default AuthorizationPolicy.
    # ACLAuthorizationPolicy is usually what you want.
    # If the app configures one explicitly then this will get overridden.
    # In auto-commit mode this needs to be set before adding an authn policy.
    authz_policy = ACLAuthorizationPolicy()
    config.set_authorization_policy(authz_policy)

    # Build a JWTAuthenticationPolicy from the deployment settings.
    settings = config.get_settings()
    authn_policy = JWTAuthenticationPolicy.from_settings(settings)
    config.set_authentication_policy(authn_policy)

    # Set the forbidden view to use the challenge() method on the policy.
    config.add_forbidden_view(authn_policy.challenge)
