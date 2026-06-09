package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtMalformedException;

import java.util.Base64;

class JwtBytesPolicy {

    static String bytesToBase64(byte[] bytes){
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static byte[] bytesFromBase64(String base64) throws JwtMalformedException {
        try{
            return Base64.getUrlDecoder().decode(base64);
        }catch (Exception e){
            throw new JwtMalformedException("Incorrect bytes encoding");
        }

    }
}
