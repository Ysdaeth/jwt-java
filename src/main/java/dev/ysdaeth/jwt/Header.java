package dev.ysdaeth.jwt;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Header extends Base64Holder {

    private Map<String, String> claims = new HashMap<>();

    public Header setKeyId(String keyId){
        claims.put("kid",keyId);
        return this;
    }

    /**
     * @return key id or null when does not exist
     */
    public String getKeyId(){ return claims.get("kid"); }

    public Header setType(JwtType jwtType){
        claims.put("typ", jwtType.name());
        return this;
    }

    /**
     * @return jwt type
     */
    public String getType(){ return claims.get("typ"); }

    public Header setAlgorithm(String alg){
        claims.put("alg", alg);
        return this;
    }

    /**
     * @return jwt type or null when does not exist
     */
    public String getAlgorithm(){ return claims.get("alg"); }

    public Header setPublicKey(byte[] verificationKey){
        String keyBase64 = Base64.getEncoder().encodeToString(verificationKey);
        claims.put("jwk",keyBase64);
        return this;
    }

    /**
     * @return computed public key or null when does not exist
     */
    public byte[] getPublicKey(){
        String keyBase64 = claims.get("jwk");
        return Base64.getDecoder().decode(keyBase64);
    }

    public Header add(String key, String value){
        claims.put(key,value);
        return this;
    }

    /**
     * @param key claim name
     * @return value or null when does not exist
     */
    public String get(String key){ return claims.get(key); }

    /**
     * Returns mutable map
     * @return map with claims
     */
    Map<String, String> getClaims(){
        return claims;
    }

    public Header setClaims(Map<String,String> claims){
        this.claims = claims;
        return this;
    }
}
