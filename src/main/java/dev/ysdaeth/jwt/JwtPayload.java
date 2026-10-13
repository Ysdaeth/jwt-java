package dev.ysdaeth.jwt;

import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
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
        if(value == null) return null;
        if(value instanceof String base64){
            try{
                return Base64.getUrlDecoder().decode(base64);
            }catch (Exception e){
                throw new ClassCastException(e.getMessage());
            }
        }
        throw new ClassCastException("Incorrect data type");
    }

    public <T> T get(String key){
        Object value = claims.get(key);
        if(value == null) return null;
        try{
            return (T) value;
        }catch (Exception e){
            throw new ClassCastException("Incorrect object type for key '%s'".formatted(key));
        }
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