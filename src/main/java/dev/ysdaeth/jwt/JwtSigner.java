package dev.ysdaeth.jwt;

import java.security.Key;

interface JwtSigner {
    Signature sign(Header header, Payload payload, Key key);
    boolean verify(Jwt jwt, Key key);
}
