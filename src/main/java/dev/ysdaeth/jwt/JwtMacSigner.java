
package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtSignatureException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.*;

public class JwtMacSigner extends JwtSigner {

    private final String algorithm;

    protected JwtMacSigner(JwtAlgorithm jwtAlgorithm, String macAlgorithm) {
        super(jwtAlgorithm);
        this.algorithm = macAlgorithm;
    }

    @Override
    protected JwtSignature createSignature(byte[] message, Key key)
            throws IllegalArgumentException, IllegalStateException {
        if (message == null) throw new IllegalArgumentException("Message cannot be null");
        if (key == null) throw new IllegalArgumentException("Key cannot be null");

        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(key);
            return new JwtSignature(mac.doFinal(message));

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "Unsupported MAC algorithm: " + algorithm, e);

        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(
                    "Invalid key for MAC algorithm: " + algorithm, e);
        }
    }

    @Override
    protected void verifyMessage(byte[] message, JwtSignature signature, Key key)
            throws JwtSignatureException, IllegalArgumentException, IllegalStateException {

        if (message == null) throw new IllegalArgumentException("Message cannot be null");
        if (signature == null) throw new IllegalArgumentException("Signature cannot be null");
        if (key == null) throw new IllegalArgumentException("Key cannot be null");

        JwtSignature expected;
        try{
            expected = createSignature(message, key);
        }catch (IllegalArgumentException e){
            throw new JwtSignatureException("Signature verification failed");
        }
        boolean matches = MessageDigest.isEqual(expected.getBytes(), signature.getBytes());

        if (!matches) throw new JwtSignatureException("Signature does not match");

    }
}
