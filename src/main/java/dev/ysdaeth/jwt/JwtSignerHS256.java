package dev.ysdaeth.jwt;

import java.security.Key;

public class JwtSignerHS256 implements JwtSigner{

    @Override
    public Signature sign(Header header, Payload payload, Key key) {
        return null;
    }

    @Override
    public boolean verify(Jwt jwt, Key key) {
        return false;
    }
}
