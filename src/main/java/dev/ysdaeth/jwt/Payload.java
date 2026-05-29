package dev.ysdaeth.jwt;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;

public class Payload {

    private final Claims claims;

    public Payload(Map<String, Object> claims){
        this.claims = new Claims(claims);
    }

    public Payload(){
        claims = new Claims();
    }

    Payload(Claims claims){
        this.claims = claims;
    }

    public Payload setIssuer(String issuer){
        claims.put("iss", issuer);
        return this;
    }

    public String getIssuer(){
        return (String) claims.get("iss");
    }

    public Payload setSubject(String subject){
        claims.put("sub", subject);
        return this;
    }

    public String getSubject(){
        return (String) claims.get("sub");
    }

    public Payload setAudience(String audience){
        claims.put("aud", audience);
        return this;
    }

    public String getAudience(){
        return (String) claims.get("aud");
    }

    public Payload setJwtId(String id){
        claims.put("jti", id);
        return this;
    }

    public String getJwtId(){
        return (String) claims.get("jti");
    }

    public Payload setIssuedAt(Instant issuedAt){
        claims.put("iat", issuedAt.getEpochSecond());
        return this;
    }

    public Instant getIssuedAt(){
        Object value = claims.get("iat");

        if(value instanceof Number number){
            return Instant.ofEpochSecond(number.longValue());
        }

        return null;
    }

    public Payload setExpireAt(Instant expiresAt){
        claims.put("exp", expiresAt.getEpochSecond());
        return this;
    }

    public Instant getExpireAt(){
        Object value = claims.get("exp");

        if(value instanceof Number number){
            return Instant.ofEpochSecond(number.longValue());
        }

        return null;
    }

    public Payload setNotBefore(Instant notBefore){
        claims.put("nbf", notBefore.getEpochSecond());
        return this;
    }

    public Instant getNotBefore(){
        Object value = claims.get("nbf");

        if(value instanceof Number number){
            return Instant.ofEpochSecond(number.longValue());
        }

        return null;
    }

    public Payload add(String key, Object value){
        claims.put(key, value);
        return this;
    }

    public Object get(String key){
        return claims.get(key);
    }

    public String getString(String key){
        Object value = claims.get(key);
        return value != null ? value.toString() : null;
    }

    public Long getLong(String key){
        Object value = claims.get(key);

        if(value instanceof Number number){
            return number.longValue();
        }

        return null;
    }

    public Boolean getBoolean(String key){
        Object value = claims.get(key);

        if(value instanceof Boolean bool){
            return bool;
        }

        return null;
    }

    /**
     * Encodes bytes to base64 and stores them as string
     */
    public Payload addBytes(String key, byte[] value){
        String base64 = Base64.getEncoder().encodeToString(value);
        claims.put(key, base64);
        return this;
    }

    /**
     * Decodes base64 string to bytes
     */
    public byte[] getBytes(String key){
        Object value = claims.get(key);

        if(value instanceof String base64){
            return Base64.getDecoder().decode(base64);
        }

        return null;
    }

    public Payload setClaims(Map<String, Object> claims){
        this.claims.clear();
        this.claims.putAll(claims);
        return this;
    }

    /**
     * Returns mutable claims map
     */
    Claims getClaims(){
        return claims;
    }
}