package dev.ysdaeth.jwt;

import java.util.HashMap;
import java.util.Map;

public class Payload {
    private Map<String, String> claims = new HashMap<>();



    /**
     * returns mutable map
     * @return map claims
     */
    Map<String,String> getClaims(){
        return claims;
    }

    public Payload setClaims(Map<String,String> claims){
        this.claims = claims;
        return this;
    }
}
