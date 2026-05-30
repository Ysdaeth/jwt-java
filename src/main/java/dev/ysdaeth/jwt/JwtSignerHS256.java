package dev.ysdaeth.jwt;

import javax.crypto.Mac;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;

public class JwtSignerHS256 extends JwtSigner {

    public JwtSignerHS256(JwtAlgorithm algorithm) {
        super(algorithm);
    }

    @Override
    protected Signature createSignature(byte[] message, Key key) {
        byte[] signatureBytes;
        try{
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            signatureBytes = mac.doFinal(message);
        }catch (Exception e){
            throw new RuntimeException("Creating JWT signature failed." + e.getMessage(), e);
        }
        return new Signature(signatureBytes);
    }

    @Override
    protected boolean verify(byte[] message, Signature signature, Key key) {
        Signature actualSignature = createSignature(message, key);
        return actualSignature.equals(signature);
    }
}
