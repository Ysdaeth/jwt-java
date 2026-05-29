package dev.ysdaeth.jwt;

import java.util.Base64;

public class Signature {
    private final byte[] signature;

    public Signature(byte[] signature){
        this.signature = signature;
    }

    public Signature(String signatureBase64){
        this(
                Base64.getDecoder().decode(signatureBase64)
        );
    }

    byte[] getBytes(){
        return signature.clone();
    }
}
