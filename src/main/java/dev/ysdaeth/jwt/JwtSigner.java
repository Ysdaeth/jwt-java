package dev.ysdaeth.jwt;

import java.security.Key;

interface JwtSigner {
    Signature createSignature(Header header, Payload payload, Key key);
    boolean verify(Header header, Payload payload, Signature signature, Key key);
}
