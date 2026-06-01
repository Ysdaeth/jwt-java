package dev.ysdaeth.jwt;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;

public class JwtSignerHS256 extends JwtSigner {

    public JwtSignerHS256() {
        super(JwtAlgorithm.HS256);
    }

    @Override
    protected JwtSignature createSignature(byte[] message, Key key) throws IllegalArgumentException {
        byte[] signatureBytes;
        try{
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            signatureBytes = mac.doFinal(message);
        }catch (Exception e){
            if(e instanceof InvalidKeyException) {
                throw new IllegalArgumentException("Could not create jwt signature, key is invalid. " + e.getMessage());
            }
            throw new RuntimeException("Creating JWT signature failed." + e.getMessage(), e);
        }
        return new JwtSignature(signatureBytes);
    }

    @Override
    protected boolean verifyMessage(byte[] message, JwtSignature signature, Key key) {
        boolean anyNull = message == null || signature == null || key == null;
        if(anyNull) return false;

        boolean isVerified;
        try {
            JwtSignature actualSignature = createSignature(message, key);
            isVerified =  actualSignature.equals(signature);
        }catch (Exception e){
            isVerified = false;
        }
        return isVerified;
    }
}
