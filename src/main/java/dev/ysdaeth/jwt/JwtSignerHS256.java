package dev.ysdaeth.jwt;

import javax.crypto.Mac;
import java.nio.ByteBuffer;
import java.security.Key;

public class JwtSignerHS256 extends JwtSigner {

    public JwtSignerHS256(JwtAlgorithm algorithm) {
        super(algorithm);
    }

    @Override
    protected Signature createSignature(byte[] header, byte[] payload, Key key) {
        return null;
    }

    @Override
    protected boolean verify(byte[] header, byte[] payload, byte[] signature, Key key) {
        return false;
    }
}
