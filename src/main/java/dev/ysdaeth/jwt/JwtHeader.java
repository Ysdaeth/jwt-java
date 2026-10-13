package dev.ysdaeth.jwt;

import java.util.Base64;
import java.util.Collection;
import java.util.Map;

public final class JwtHeader {

    private final JwtClaims claims;

    public JwtHeader(Map<String, Object> claims){
        this.claims = new JwtClaims(claims);
    }

    JwtHeader(JwtClaims claims){
        this.claims = claims;
    }

    public JwtHeader(){
        this.claims = new JwtClaims();
    }

    public JwtHeader setKeyId(String keyId){
        claims.put("kid",keyId);
        return this;
    }

    /**
     * @return key id or null when does not exist
     */
    public String getKeyId(){
        return claims.get("kid");
    }

    public void setType(String type){
        claims.put("typ", type);
    }

    /**
     * @return jwt type
     */
    public String getType(){
        return claims.get("typ");
    }

    public void setAlgorithm(String alg){
        claims.put("alg", alg);
    }

    /**
     * @return jwt type or null when does not exist
     */
    public String getAlgorithm(){
        return claims.get("alg");
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
        String base64 = claims.get("jwk");
        if(base64 == null) return null;
        return Base64.getUrlDecoder().decode(base64);
    }

    public void add(String key, String value){
        claims.put(key,value);
    }

    public void add(String key, Number value){
        claims.put(key,value);
    }

    public void add(String key, Boolean value){
        claims.put(key,value);
    }

    /**
     * It supports Collection values that are other Collection or Map and
     * stores it as immutable copy of the collection. If object in collection is
     * mutable (apart from Collection or Map) it will not prevent from changing it,
     * so it is preferred to keep immutable objects as values.
     * @param key name of the field
     * @param value map
     */
    public void add(String key, Collection<?> value){
        claims.put(key, value);
    }

    /**
     * It supports Map values that are other Maps or Collections and
     * stores it as immutable copy of the collection. If object in collection is
     * mutable (apart from Collection or Map) it  will not prevent from changing its fields,
     * so it is preferred to keep immutable objects as values.
     * @param key name of the field
     * @param value map
     */
    public void add(String key, Map<?,?> value){
        claims.put(key, value);
    }

    /**
     * @param key claim name
     * @return value or null when does not exist
     */
    public Object get(String key){
        return claims.get(key);
    }

    JwtClaims getClaims() {
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
        if(obj instanceof JwtHeader other){
            return claims.equals(other.claims);
        }
        return false;
    }
}
