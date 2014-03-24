===============
pyramid_jwtauth
===============

NOTE: This is an early version of the code is the library is likely to change.

This is a Pyramid authenitcation plugin for JSON Web Token (JWT)
Authentication:

    http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html

To access resources using JWT Access Authentication, the client must have
obtained a JWT to make signed requests to the server.  This library also makes
JSON Web Tokens for the client.  The Token can be opaque to client although,
unless it is encrypted, the client can read the claims made in the token.

When accessing a protected resource, the server will generate a 401 challenge
response with the scheme "JWT" as follows::

    > GET /protected_resource HTTP/1.1
    > Host: example.com

    < HTTP/1.1 401 Unauthorized
    < WWW-Authenticate: JWT

The client will use their JWT to build a request signature and
include it in the Authorization header like so::

    > GET /protected_resource HTTP/1.1
    > Host: example.com
    > Authorization: JWT token=eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
     cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

    < HTTP/1.1 200 OK
    < Content-Type: text/plain
    <
    < For your eyes only:  secret data!

(NB depending on the number of claims in the JWT the token can get large.
For all practical purposes, it should be kept short.)

This plugin uses the PyJWT library for verifying JWTs:

    http://github.com/progrium/pyjwt

Also see the library for generating the JWT for the client in the first place
although any language can be used to generate it.

-----------
Inspiration
-----------

This module is *heavily* based on (and copied from) the Mozilla Services
pyramid_macauth package and macauthlib package:

    https://github.com/mozilla-services/pyramid_macauth

    https://github.com/mozilla-services/macauthlib

Without it, I would not have been able to make the small number of
modifications to this package and get it to work with Pyramid.

-------
Licence
-------

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this file,
You can obtain one at http://mozilla.org/MPL/2.0/.
