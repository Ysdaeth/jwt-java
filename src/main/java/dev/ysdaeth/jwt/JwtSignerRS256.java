package dev.ysdaeth.jwt;

import java.security.*;

public class JwtSignerRS256 extends JwtSigner {

    /**
     * see {@link JwtAlgorithm}
     */
    protected JwtSignerRS256() {
        super(JwtAlgorithm.RS256);
    }

    @Override
    protected JwtSignature createSignature(byte[] message, Key key) {
        PrivateKey privateKey;
        if(key instanceof PrivateKey) privateKey = (PrivateKey) key;
        else throw new IllegalArgumentException (
                "Key must be instance of '%s' , but provided was '%s' "
                        .formatted(PrivateKey.class, key.getClass()) );

        byte[] signBytes;
        try{
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(privateKey);
            sign.update(message);
            signBytes = sign.sign();
        }catch (Exception e){
            throw new RuntimeException("Failed to create signature. "+ e.getMessage());
        }

        return new JwtSignature(signBytes);
    }

    @Override
    protected boolean verifyMessage(byte[] message, JwtSignature jwtSignature, Key key) {
        PublicKey publicKey;
        if(key instanceof PublicKey) publicKey = (PublicKey) key;
        else return false;

        try{
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(publicKey);
            sign.update(message);
            return sign.verify(jwtSignature.getBytes());
        } catch (Exception e) {
            return false;
        }
    }
}
