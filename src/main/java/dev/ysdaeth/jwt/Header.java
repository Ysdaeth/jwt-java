package dev.ysdaeth.jwt;

import java.util.Base64;
import java.util.Map;

public final class Header {

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

    public void setType(String type){
        claims.put("typ", type);
    }

    /**
     * @return jwt type
     */
    public String getType(){
        Object value = claims.get("typ");
        if(value instanceof String) return (String) value;
        return null;
    }

    public void setAlgorithm(String alg){
        claims.put("alg", alg);
    }

    /**
     * @return jwt type or null when does not exist
     */
    public String getAlgorithm(){
        Object value = claims.get("alg");
        if(value instanceof String) return (String) value;
        return null;
    }

    public void setPublicKey(byte[] verificationKey){
        String keyBase64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(verificationKey);
        claims.put("jwk", keyBase64);
    }

    /**
     * @return computed public key or null when does not exist
     */
    public byte[] getPublicKey(){
        Object value = claims.get("jwk");
        if(value instanceof String base64){
            return Base64.getUrlDecoder().decode(base64);
        }
        return null;
    }

    public void add(String key, Object value){
        claims.put(key,value);
    }

    /**
     * @param key claim name
     * @return value or null when does not exist
     */
    public Object get(String key){
        return claims.get(key);
    }

    Claims getClaims() {
        return claims;
    }

    /**
     * Locks claims to be immutable
     */
    void lock(){
        claims.lock();
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof Header other){
            return claims.equals(other.claims);
        }
        return false;
    }
}
