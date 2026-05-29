package dev.ysdaeth.jwt;

import java.util.HashMap;
import java.util.Map;

class Claims {
    private boolean isLocked = false;
    private final Map<String, Object> claims;

    public Claims(Map<String,Object> claims){
        this.claims = new HashMap<>(claims);
    }

    public Claims(){
        claims = new HashMap<>();
    }

    Object get(String key){
        return claims.get(key);
    }

    void put(String key, Object value){
        if(isLocked) throw new JwtStateException(
                "Claims cannot be changed when JWT is signed");
        this.claims.put(key, value);
    }

    void putAll(Map<String,Object> claims){
        if(isLocked) throw new JwtStateException(
                "Claims cannot be changed when JWT is signed");
        this.claims.putAll(claims);
    }

    void lock(){
        isLocked = true;
    }

    void clear(){
        if(isLocked) throw new JwtStateException(
                "Claims cannot be changed when JWT is signed");
        claims.clear();
    }
}
