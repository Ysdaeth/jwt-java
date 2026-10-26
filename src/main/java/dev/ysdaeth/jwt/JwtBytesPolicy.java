package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtMalformedException;

import java.util.Base64;

/**
 * Bytes conversion policy class. It converts bytes to Base64 url safe encoding and backward.
 */
class JwtBytesPolicy {

    /**
     * Creates base64 url safe bytes encoding
     * @param bytes bytes to encode to base64 url safe
     * @return base64 url safe no padding
     */
    static String bytesToBase64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Creates bytes from base64 url safe
     * @param base64 Base64 url safe encoded bytes
     * @return array of bytes
     * @throws JwtMalformedException when base64 is incorrect.
     */
    static byte[] bytesFromBase64(String base64) throws JwtMalformedException {
        try{
            return Base64.getUrlDecoder().decode(base64);
        }catch (Exception e){
            throw new JwtMalformedException("Incorrect bytes encoding");
        }

    }
}
