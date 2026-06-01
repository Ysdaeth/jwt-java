package dev.ysdaeth.jwt;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;

public final class JwtPayload {

    private final JwtClaims claims;

    public JwtPayload(Map<String, Object> claims){
        this.claims = new JwtClaims(claims);
    }

    public JwtPayload(){
        claims = new JwtClaims();
    }

    JwtPayload(JwtClaims claims){
        this.claims = claims;
    }

    public void setIssuer(String issuer){
        claims.put("iss", issuer);
    }

    public String getIssuer(){
        return (String) claims.get("iss");
    }

    public void setSubject(String subject){
        claims.put("sub", subject);
    }

    public String getSubject(){
        return (String) claims.get("sub");
    }

    public void setAudience(String audience){
        claims.put("aud", audience);
    }

    public String getAudience(){
        return (String) claims.get("aud");
    }

    public void setJwtId(String id){
        claims.put("jti", id);
    }

    public String getJwtId(){
        return (String) claims.get("jti");
    }

    public void setIssuedAt(Instant issuedAt){
        claims.put("iat", issuedAt.getEpochSecond());
    }

    public Instant getIssuedAt(){
        Object value = claims.get("iat");

        if(value instanceof Number number){
            return Instant.ofEpochSecond(number.longValue());
        }

        return null;
    }

    public void setExpiresAt(Instant expiresAt){
        claims.put("exp", expiresAt.getEpochSecond());
    }

    public Instant getExpireAt(){
        Object value = claims.get("exp");

        if(value instanceof Number number){
            return Instant.ofEpochSecond(number.longValue());
        }

        return null;
    }

    public void setNotBefore(Instant notBefore){
        claims.put("nbf", notBefore.getEpochSecond());
    }

    public Instant getNotBefore(){
        Object value = claims.get("nbf");

        if(value instanceof Number number){
            return Instant.ofEpochSecond(number.longValue());
        }

        return null;
    }

    public void add(String key, Object value){
        claims.put(key, value);
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
    public void addBytes(String key, byte[] value){
        String base64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value);
        claims.put(key, base64);
    }

    /**
     * Decodes base64 string to bytes
     */
    public byte[] getBytes(String key){
        Object value = claims.get(key);

        if(value instanceof String base64){
            return Base64.getUrlDecoder().decode(base64);
        }

        return null;
    }

    public void setClaims(Map<String, Object> claims){
        this.claims.clear();
        this.claims.putAll(claims);
    }

    JwtClaims getClaims() {
        return claims;
    }

    /**
     * Locks claims to be immutable
     */
    void lock() {
        claims.lock();
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof JwtPayload other){
            return claims.equals(other.claims);
        }
        return false;
    }

}