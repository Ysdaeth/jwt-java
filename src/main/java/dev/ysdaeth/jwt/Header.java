package dev.ysdaeth.jwt;

import java.util.Base64;
import java.util.Map;

public class Header {

    private final Claims claims;

    public Header(Map<String, Object> claims){
        this.claims = new Claims(claims);
    }

    Header(Claims claims){
        this.claims = claims;
    }

    public Header(){
        this.claims = new Claims();
    }

    public Header setKeyId(String keyId){
        claims.put("kid",keyId);
        return this;
    }

    /**
     * @return key id or null when does not exist
     */
    public String getKeyId(){
        Object value = claims.get("kid");
        if(value instanceof String) return (String) value;
        return null;
    }

    public Header setType(String type){
        claims.put("typ", type);
        return this;
    }

    /**
     * @return jwt type
     */
    public String getType(){
        Object value = claims.get("typ");
        if(value instanceof String) return (String) value;
        return null;
    }

    public Header setAlgorithm(String alg){
        claims.put("alg", alg);
        return this;
    }

    /**
     * @return jwt type or null when does not exist
     */
    public String getAlgorithm(){
        Object value = claims.get("alg");
        if(value instanceof String) return (String) value;
        return null;
    }

    public Header setPublicKey(byte[] verificationKey){
        String keyBase64 = Base64.getEncoder().encodeToString(verificationKey);
        claims.put("jwk", keyBase64);
        return this;
    }

    /**
     * @return computed public key or null when does not exist
     */
    public byte[] getPublicKey(){
        Object value = claims.get("jwk");
        if(value instanceof String base64){
            return Base64.getDecoder().decode(base64);
        }
        return null;
    }

    public Header add(String key, String value){
        claims.put(key,value);
        return this;
    }

    /**
     * @param key claim name
     * @return value or null when does not exist
     */
    public Object get(String key){
        return claims.get(key);
    }

    /**
     * Returns mutable map
     * @return map with claims
     */
    Claims getClaims(){
        return claims;
    }
}
