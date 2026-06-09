package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtStateException;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Holder for claims
 * It is possible to lock the claims, which makes it immutable.
 */
final class JwtClaims {
    private boolean isLocked = false;
    private final Map<String, Object> claimsMap;

    public JwtClaims(Map<String,Object> claimsMap){
        this.claimsMap = new HashMap<>(claimsMap);
    }

    public JwtClaims(){
        claimsMap = new HashMap<>();
    }

    Object get(String key){
        return claimsMap.get(key);
    }

    void put(String key, Object value){
        if(isLocked) throw new JwtStateException(
                "Claims cannot be changed when JWT is signed");
        this.claimsMap.put(key, value);
    }

    void putAll(Map<String,Object> claims){
        if(isLocked) throw new JwtStateException(
                "Claims cannot be changed when JWT is signed");
        this.claimsMap.putAll(claims);
    }

    void lock(){
        isLocked = true;
    }

    void clear(){
        if(isLocked) throw new JwtStateException(
                "Claims cannot be changed when JWT is signed");
        claimsMap.clear();
    }

    /**
     * Should always be package private.
     * When this instance is locked it returns a copy map of claims, otherwise it returns
     * reference to the original map. Exposing COPY of the map may potentially be unsecure
     * if object in the map is mutable like Byte[]. Make sure to make it immutable
     * before setting it as a claim.
     * @return copy of the map if this instance is locked, otherwise reference to the map.
     */
    Map<String,Object> getMap(){
        if(isLocked) return new HashMap<>(claimsMap);
        return claimsMap;
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof JwtClaims other){
            Map<String,Object> otherMap = other.getMap();
            return mapsEqual(claimsMap, otherMap);
        }
        return false;
    }
    private static boolean mapsEqual(Map<String, Object> src, Map<String, Object> target){
        if(src.size() != target.size()) return false;
        Set<String> srcKeySet = src.keySet();

        for(String key : srcKeySet){
            if( !target.containsKey(key) ) return false;
            Object srcObj = src.get(key);
            Object targetObj = target.get(key);

            boolean equals = valuesEqual(srcObj, targetObj);
            if(!equals) return false;
        }
        return true;
    }

    private static boolean valuesEqual(Object srcObj, Object targetObj) {
        if (srcObj == targetObj) return true;
        if (srcObj == null || targetObj == null) return false;

        if (srcObj instanceof Number n1 && targetObj instanceof Number n2) {
            return Double.compare(n1.doubleValue(), n2.doubleValue()) == 0;
        }

        return srcObj.equals(targetObj);
    }
}
