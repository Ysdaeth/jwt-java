package dev.ysdaeth.jwt;

import java.util.Arrays;
import java.util.Base64;

public class Signature {
    private final byte[] signature;

    public Signature(byte[] signature){
        this.signature = signature;
    }

    public Signature(String signature){
        this.signature = Base64.getUrlDecoder().decode(signature);
    }

    byte[] getBytes(){
        return signature.clone();
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof Signature other){
            return Arrays.equals(signature, other.signature);
        }
        return false;
    }
}
