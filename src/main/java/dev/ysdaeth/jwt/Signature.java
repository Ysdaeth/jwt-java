package dev.ysdaeth.jwt;

import java.util.Base64;

public class Signature extends Base64Holder{
    private final byte[] signature;

    public Signature(byte[] signature){
        setBase64( Base64.getEncoder().encodeToString(signature) );
        this.signature = signature;
    }

    public Signature(String signatureBase64){
        setBase64( signatureBase64 );
        this.signature = Base64.getDecoder().decode(signatureBase64);
    }

    public byte[] getBytes() {
        return signature.clone();
    }

    @Override
    void setBase64(String base64){
        throw new RuntimeException("Signature cannot be re-assigned");
    }
}
