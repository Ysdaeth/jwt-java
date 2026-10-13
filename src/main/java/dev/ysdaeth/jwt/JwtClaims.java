package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.JwtStateException;

import java.util.*;

/**
 * Holder for claims
 * It is possible to lock the claims, which makes it immutable.
 */
final class JwtClaims {
    private boolean isLocked = false;
    private final Map<String, Object> claimsMap;

    public JwtClaims(Map<String,Object> claimsMap){
        this.claimsMap = new HashMap<>();
        putAll(claimsMap);
    }

    public JwtClaims(){
        claimsMap = new HashMap<>();
    }

    <T> T get(String key) throws ClassCastException {
        Object value = claimsMap.get(key);
        return (T) defensiveCopy(value);
    }

    /**
     * Object should be a {@link Collection}, {@link Map} or
     * immutable object like CharSequence, Integer, Boolean otherwise it may be possible
     * to change object state by the reference.
     * @param key name of the claim
     * @param value value of the claim, Collection, Map or immutable Object
     * @throws JwtStateException when this instance is locked
     */
    private void putValue(String key, Object value) throws JwtStateException {
        if(isLocked) throw new JwtStateException(
                "Locked claims cannot be changed");
        this.claimsMap.put(key, defensiveCopy(value));
    }

    void put(String key, Collection<?> value){
        putValue(key, value);
    }

    void put(String key, Map<?,?> value){
        putValue(key, value);
    }

    void put(String key, String value) throws JwtStateException {
        putValue(key, value);
    }

    void put(String key, Number value){
        putValue(key, value);
    }

    void put(String key, Boolean value){
        putValue(key, value);
    }

    void putAll(Map<String,Object> claimsMap) {
        for(Map.Entry<String, Object> e: claimsMap.entrySet()){
            putValue(e.getKey(), e.getValue());
        }
    }

    void lock(){
        isLocked = true;
    }

    void clear() throws JwtStateException {
        if(isLocked) throw new JwtStateException(
                "Locked claims cannot be changed");
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
            Map<String,Object> otherClaimsMap = other.getMap();
            return areEqualMaps(claimsMap, otherClaimsMap);
        }
        return false;
    }

    private static boolean areEqualMaps(Map<String, Object> src, Map<String, Object> target){
        if(src.size() != target.size()) return false;
        Set<String> srcKeySet = src.keySet();

        for(String key : srcKeySet){
            if( !target.containsKey(key) ) return false;
            Object srcObj = src.get(key);
            Object targetObj = target.get(key);

            boolean equals = areEqualValues(srcObj, targetObj);
            if(!equals) return false;
        }
        return true;
    }

    private static boolean areEqualValues(Object srcObj, Object targetObj) {
        if (srcObj == targetObj) return true;
        if (srcObj == null || targetObj == null) return false;

        if (srcObj instanceof Number n1 && targetObj instanceof Number n2) {
            return Double.compare(n1.doubleValue(), n2.doubleValue()) == 0;
        }

        return srcObj.equals(targetObj);
    }

    private static Object defensiveCopy(Object value){
        if(value instanceof Map<?,?> map){
            Map<Object,Object> copy = new HashMap<>();
            map.forEach(
                    (k,v)-> copy.put(k,defensiveCopy(v))
            );
            return copy;
        }

        if(value instanceof Collection<?> collection){
            return collection.stream().map(JwtClaims::defensiveCopy).toList();
        }

        return value;
    }
}
