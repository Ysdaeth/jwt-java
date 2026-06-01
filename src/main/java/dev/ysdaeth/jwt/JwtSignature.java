package dev.ysdaeth.jwt;

import java.util.Arrays;
import java.util.Base64;

public class JwtSignature {
    private final byte[] signature;

    public JwtSignature(byte[] signature){
        this.signature = signature;
    }

    byte[] getBytes(){
        return signature.clone();
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof JwtSignature other){
            return Arrays.equals(signature, other.signature);
        }
        return false;
    }
}
