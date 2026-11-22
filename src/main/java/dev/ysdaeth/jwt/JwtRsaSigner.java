
package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtSignatureException;

import java.security.*;

public class JwtRsaSigner extends JwtSigner {

    private final String algorithm;

    protected JwtRsaSigner(JwtAlgorithm jwtAlgorithm, String signatureAlgorithm) {
        super(jwtAlgorithm);
        this.algorithm = signatureAlgorithm;
    }

    @Override
    protected JwtSignature createSignature(byte[] message, Key key)
            throws IllegalArgumentException, IllegalStateException, JwtSignatureException{
        if (message == null) throw new IllegalArgumentException("Message cannot be null");

        if (!(key instanceof PrivateKey privateKey)) {
            throw new IllegalArgumentException("Key must be a PrivateKey");
        }

        try {
            Signature signer = Signature.getInstance(algorithm);
            signer.initSign(privateKey);
            signer.update(message);
            return new JwtSignature(signer.sign());

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "Unsupported signature algorithm: " + algorithm, e);

        } catch (InvalidKeyException | SignatureException e) {
            throw new JwtSignatureException(
                    "Failed to create RSA signature", e);
        }
    }

    @Override
    protected void verifyMessage(byte[] message, JwtSignature jwtSignature, Key key)
            throws JwtSignatureException, IllegalStateException {

        if (message == null) throw new IllegalArgumentException("Message cannot be null");
        if (jwtSignature == null) throw new IllegalArgumentException("Signature cannot be null");

        if (!(key instanceof PublicKey publicKey)) {
            throw new JwtSignatureException("Invalid key");
        }

        try {
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(message);

            if (!verifier.verify(jwtSignature.getBytes())) {
                throw new JwtSignatureException("JWT signature does not match");
            }

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unsupported signature algorithm: " + algorithm, e);

        } catch (InvalidKeyException | SignatureException e) {
            throw new JwtSignatureException("Failed to verify JWT signature", e);
        }
    }
}

