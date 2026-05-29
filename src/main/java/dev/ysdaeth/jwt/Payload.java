package dev.ysdaeth.jwt;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Payload {
    private Map<String, String> claims = new HashMap<>();

    public Payload(Map<String, String> claims){
        this.claims.putAll(claims);
    }
    public Payload(){

    }

    public Payload setIssuer(String issuer){
        claims.put("iss", issuer);
        return this;
    }

    public String getIssuer(){
        return claims.get("iss"); }

    public Payload setSubject(String subject){
        claims.put("sub", subject);
        return this;
    }

    public String getSubject(){
        return claims.get("sub"); }

    public Payload setAudience(String audience){
        claims.put("aud", audience);
        return this;
    }

    public String getAudience(){
        return claims.get("aud"); }

    public Payload setJwtId(String id){
        claims.put("jti", id);
        return this;
    }

    public String getJwtId(){
        return claims.get("jti");}

    public Payload setIssuedAt(Instant issuedAt){
        String time = issuedAt.toString();
        claims.put("iat", time);
        return this;
    }

    public Instant getIssuedAt(){
        String time = claims.get("iat");
        if(time != null) return Instant.parse(time);
        return null;
    }

    public Payload setExpireAt(Instant expiresAt){
        String time = expiresAt.toString();
        claims.put("exp", time);
        return this;
    }

    public Instant getExpireAt(){
        String time = claims.get("exp");
        if(time != null) return Instant.parse(time);
        return null;
    }

    public Payload setNotBefore(Instant notBefore){
        String time = notBefore.toString();
        claims.put("nbf", time);
        return this;
    }

    public Instant getNotBefore(){
        String time = claims.get("nbf");
        if(time != null) return Instant.parse(time);
        return null;
    }

    public Payload add(String key, String value){
        claims.put(key,value);
        return this;
    }

    public String get(String key){
        return claims.get(key); }

    /**
     * Encodes bytes to base64 and set it as a claim with specified name
     * @param key claim name
     * @param value claim value, base64 encoded bytes
     * @return this instance
     */
    public Payload addBytes(String key, byte[] value){
        String base64 = Base64.getEncoder().encodeToString(value);
        claims.put(key, base64);
        return this;
    }

    /**
     * Looks for specified field passed as an argument, and parses value from base64 to bytes
     * @param key claim name
     * @return byte array
     */
    public byte[] getBytes(String key){
        String base64 = claims.get(key);
        if(base64 != null) return Base64.getDecoder().decode(base64);
        return null;
    }

    public Payload setClaims(Map<String,String> claims){
        this.claims = claims;
        return this;
    }

    /**
     * returns mutable map
     * @return map claims
     */
    Map<String,String> getClaims(){
        return claims;
    }
}
