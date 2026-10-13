package dev.ysdaeth.jwt;


import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JwtClaimsTest {

    @Test
    void claimsCollectionShouldBeImmutable(){
        JwtClaims claims = new JwtClaims();
        List<String> list = new ArrayList<>();
        list.add("one");
        list.add("two");

        claims.put("list", list);

        list.add("three");

        List<String> immutableList = claims.get("list");
        assertFalse(immutableList.contains("three"), "Claims Collection was mutated from outside");
    }

    @Test
    void claimsMapShouldBeImmutable(){
        Map<String,Byte> map = new HashMap<>();
        map.put("a",(byte)0x01);

        JwtClaims claims = new JwtClaims();
        claims.put("map", map);
        map.put("b",(byte)0x02);

        Map<String,Byte> immutableMap = claims.get("map");
        assertFalse(immutableMap.containsKey("b"),"Claims Map was mutated from outside");
    }

    @Test
    void claims_buildWithConstructor_shouldBeImmutable(){
        Map<String,Object> claimsMap = new HashMap<>();
        claimsMap.put("a","abc");
        JwtClaims claims = new JwtClaims(claimsMap);
        claimsMap.put("a","def");

        assertTrue(
                ()->claims.get("a").equals("abc"),
                "Claims was changed when passed map of claims in the constructor"
        );
    }

    @Test
    void generalDataTypesShouldBeSupported(){
        Map<String,Object> claimsMap = new HashMap<>();
        claimsMap.put("byte",(byte)0x1);
        claimsMap.put("int", 1);
        claimsMap.put("boolean",true);
        claimsMap.put("string","1");
        claimsMap.put("float",1f);
        claimsMap.put("double",1d);

        JwtClaims claims = new JwtClaims(claimsMap);

        assertDoesNotThrow(()->{Byte x = claims.get("byte");});
        assertDoesNotThrow(()->{Integer x = claims.get("int");});
        assertDoesNotThrow(()->{Boolean x = claims.get("boolean");});
        assertDoesNotThrow(()->{String x = claims.get("string");});
        assertDoesNotThrow(()->{Float x = claims.get("float");});
        assertDoesNotThrow(()->{Double x = claims.get("double");});
    }

    @Test
    void get_shouldReturnDataType_Byte(){
        JwtClaims claims = new JwtClaims();
        claims.put("key",(byte)0x1);
        assertDoesNotThrow(()-> {Byte value = claims.get("key");},message("Byte"));
        assertDoesNotThrow(()-> {byte value = claims.get("key");},message("byte"));
    }

    @Test
    void get_shouldReturnDataType_Integer(){
        JwtClaims claims = new JwtClaims();
        claims.put("key",1);
        assertDoesNotThrow(()-> {Integer value = claims.get("key");},message("Integer"));
        assertDoesNotThrow(()-> {int value = claims.get("key");},message("int"));
    }

    @Test
    void get_shouldReturnDataType_Boolean(){
        JwtClaims claims = new JwtClaims();
        claims.put("key",false);
        assertDoesNotThrow(()-> {Boolean value = claims.get("key");},message("Boolean"));
        assertDoesNotThrow(()-> {boolean value = claims.get("key");},message("boolean"));
    }

    @Test
    void get_shouldReturnDataType_String(){
        JwtClaims claims = new JwtClaims();
        claims.put("key","string");
        assertDoesNotThrow(()-> {String value = claims.get("key");},message("String"));
    }

    @Test
    void get_shouldReturnDataType_Float(){
        JwtClaims claims = new JwtClaims();
        claims.put("key",1f);
        assertDoesNotThrow(()-> {Float value = claims.get("key");},message("Float"));
        assertDoesNotThrow(()-> {float value = claims.get("key");},message("float"));
    }

    @Test
    void get_shouldReturnDataType_Double(){
        JwtClaims claims = new JwtClaims();
        claims.put("key",1d);
        assertDoesNotThrow(()-> {Double value = claims.get("key");},message("Double"));
        assertDoesNotThrow(()-> {double value = claims.get("key");},message("double"));
    }

    private static String message(String dataType){
        return "Claims failed to cast data type to '%s'".formatted(dataType);
    }
}
