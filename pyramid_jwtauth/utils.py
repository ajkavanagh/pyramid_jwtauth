# utils for pyramid_jwtauth

# This code heavily borrowed from:
# https://github.com/mozilla-services/macauthlib

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Low-level utility functions for pyramid_jwtauth

"""

import sys
import re
import functools
import base64
import webob

requests = None
try:
    import requests
except ImportError:   # pragma nocover
    pass

if sys.version_info > (3,):  # pragma: nocover

    def iteritems(d):
        """Efficiently iterate over dict items."""
        return d.items()

    def b64encode(data):
        """Base64-encode bytes data into a native string."""
        return base64.b64encode(data).decode("ascii")

else:  # pragma: nocover

    def iteritems(d):  # NOQA
        """Efficiently iterate over dict items."""
        return d.iteritems()

    def b64encode(data):  # NOQA
        """Base64-encode bytes data into a native string."""
        return base64.b64encode(data)


# Regular expression matching a single param in the HTTP_AUTHORIZATION header.
# This is basically <name>=<value> where <value> can be an unquoted token,
# an empty quoted string, or a quoted string where the ending quote is *not*
# preceded by a backslash.
_AUTH_PARAM_RE = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
_AUTH_PARAM_RE = re.compile(r"^\s*" + _AUTH_PARAM_RE + r"\s*$")

# Regular expression matching an unescaped quote character.
_UNESC_QUOTE_RE = r'(^")|([^\\]")'
_UNESC_QUOTE_RE = re.compile(_UNESC_QUOTE_RE)

# Regular expression matching a backslash-escaped characer.
_ESCAPED_CHAR = re.compile(r"\\.")


def parse_authz_header(request, *default):
    """Parse the authorization header into an identity dict.

    This function can be used to extract the Authorization header from a
    request and parse it into a dict of its constituent parameters.  The
    auth scheme name will be included under the key "scheme", and any other
    auth params will appear as keys in the dictionary.

    For example, given the following auth header value:

        'Digest realm="Sync" userame=user1 response="123456"'

    This function will return the following dict:

        {"scheme": "Digest", realm: "Sync",
         "username": "user1", "response": "123456"}

    """
    # This outer try-except catches ValueError and
    # turns it into return-default if necessary.
    try:
        # Grab the auth header from the request, if any.
        authz = request.environ.get("HTTP_AUTHORIZATION")
        if authz is None:
            raise ValueError("Missing auth parameters")
        scheme, kvpairs_str = authz.split(None, 1)
        # Split the parameters string into individual key=value pairs.
        # In the simple case we can just split by commas to get each pair.
        # Unfortunately this will break if one of the values contains a comma.
        # So if we find a component that isn't a well-formed key=value pair,
        # then we stitch bits back onto the end of it until it is.
        kvpairs = []
        if kvpairs_str:
            for kvpair in kvpairs_str.split(","):
                if not kvpairs or _AUTH_PARAM_RE.match(kvpairs[-1]):
                    kvpairs.append(kvpair)
                else:
                    kvpairs[-1] = kvpairs[-1] + "," + kvpair
            if not _AUTH_PARAM_RE.match(kvpairs[-1]):
                raise ValueError('Malformed auth parameters')
        # Now we can just split by the equal-sign to get each key and value.
        params = {"scheme": scheme}
        for kvpair in kvpairs:
            (key, value) = kvpair.strip().split("=", 1)
            # For quoted strings, remove quotes and backslash-escapes.
            if value.startswith('"'):
                value = value[1:-1]
                if _UNESC_QUOTE_RE.search(value):
                    raise ValueError("Unescaped quote in quoted-string")
                value = _ESCAPED_CHAR.sub(lambda m: m.group(0)[1], value)
            params[key] = value
        return params
    except ValueError:
        if default:
            return default[0]
        raise


def strings_differ(string1, string2):
    """Check whether two strings differ while avoiding timing attacks.

    This function returns True if the given strings differ and False
    if they are equal.  It's careful not to leak information about *where*
    they differ as a result of its running time, which can be very important
    to avoid certain timing-related crypto attacks:

        http://seb.dbzteam.org/crypto/python-oauth-timing-hmac.pdf

    """
    if len(string1) != len(string2):
        return True
    invalid_bits = 0
    for a, b in zip(string1, string2):
        invalid_bits += ord(a) ^ ord(b)
    return invalid_bits != 0


def normalize_request_object(func):
    """Decorator to normalize request into a WebOb request object.

    This decorator can be applied to any function taking a request object
    as its first argument, and will transparently convert other types of
    request object into a webob.Request instance.  Currently supported
    types for the request object are:

        * webob.Request objects
        * requests.Request objects
        * WSGI environ dicts
        * bytestrings containing request data
        * file-like objects containing request data

    If the input request object is mutable, then any changes that the wrapped
    function makes to the request headers will be written back to it at exit.
    """
    @functools.wraps(func)
    def wrapped_func(request, *args, **kwds):
        orig_request = request
        # Convert the incoming request object into a webob.Request.
        if isinstance(orig_request, webob.Request):
            pass
        # A requests.PreparedRequest object?
        elif requests and isinstance(orig_request, requests.PreparedRequest):
            # Copy over only the details needed for the signature.
            # WebOb doesn't code well with bytes header names,
            # so we have to be a little careful.
            request = webob.Request.blank(orig_request.url)
            request.method = orig_request.method
            for k, v in iteritems(orig_request.headers):
                if not isinstance(k, str):
                    k = k.decode('ascii')
                request.headers[k] = v
        # A WSGI environ dict?
        elif isinstance(orig_request, dict):
            request = webob.Request(orig_request)
        # A bytestring?
        elif isinstance(orig_request, bytes):
            request = webob.Request.from_bytes(orig_request)
        # A file-like object?
        elif all(hasattr(orig_request, attr) for attr in ("read", "readline")):
            request = webob.Request.from_file(orig_request)

        # The wrapped function might modify headers.
        # Write them back if the original request object is mutable.
        try:
            return func(request, *args, **kwds)
        finally:
            if requests and isinstance(orig_request, requests.PreparedRequest):
                orig_request.headers.update(request.headers)

    return wrapped_func
