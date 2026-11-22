package dev.ysdaeth.jwt;

import static org.junit.jupiter.api.Assertions.*;

import dev.ysdaeth.jwt.exception.JwtSecurityException;
import dev.ysdaeth.jwt.exception.JwtStateException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class JwtTest {

    @ParameterizedTest
    @MethodSource("algorithmKeys")
    void sign_shouldNotThrow_onValidKey(JwtAlgorithm algorithm, Jwt jwt, Key signKey, Key verifyKey){
        assertDoesNotThrow(()->{
            jwt.sign(signKey, algorithm);
        });
    }

    @ParameterizedTest
    @MethodSource("algorithmKeys")
    void sign_shouldResolveAlgorithm(JwtAlgorithm algorithm, Jwt jwt, Key signKey, Key verifyKey){
        assertDoesNotThrow(()->{
            String token = jwt.sign(signKey);
            Jwt.parse(token,verifyKey);
        });
    }

    @ParameterizedTest
    @MethodSource("algorithmKeys")
    void sign_shouldThrowSecurityException_onInvalidKey(JwtAlgorithm algorithm, Jwt jwt, Key signKey, Key verifyKey) throws Exception {
        Key invalidKey;
        if(algorithm.name().startsWith("RS")){
            invalidKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        }
        else invalidKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();

        assertThrows(IllegalArgumentException.class, ()->{
            jwt.sign(invalidKey, algorithm);
        });
    }

    @ParameterizedTest
    @MethodSource("algorithmKeys")
    void parse_shouldNotThrow_onValidKey(JwtAlgorithm algorithm, Jwt jwt, Key signKey, Key verifyKey){
        String token =  TestUtils.loadToken(algorithm);

        assertDoesNotThrow(()->{
            Jwt.parse(token, verifyKey);
        });
    }

    @ParameterizedTest
    @MethodSource("algorithmKeys")
    void parse_shouldThrow_onInvalidKey(JwtAlgorithm algorithm, Jwt jwt, Key signKey, Key verifyKey) throws Exception {
        String token =  jwt.sign(signKey, algorithm);
        Key invalidKey;
        if(algorithm.name().startsWith("RS")){
            invalidKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        }
        else invalidKey = KeyPairGenerator.getInstance("RSA").genKeyPair().getPublic();
        assertThrows(JwtSecurityException.class, ()->{
            Jwt.parse(token, invalidKey);
        });
    }

    @ParameterizedTest
    @MethodSource("algorithmKeys")
    void parse_shouldThrow_onIncorrectKey(JwtAlgorithm algorithm, Jwt jwt, Key signKey, Key verifyKey) throws Exception {
        String token =  jwt.sign(signKey, algorithm);
        Key incorrectKey;
        if(signKey instanceof PrivateKey){
            incorrectKey = KeyPairGenerator.getInstance(verifyKey.getAlgorithm()).genKeyPair().getPublic();
        }
        else incorrectKey = KeyGenerator.getInstance(verifyKey.getAlgorithm()).generateKey();

        assertThrows(JwtSecurityException.class, ()->{
            Jwt.parse(token, incorrectKey);
        });
    }

    @ParameterizedTest
    @MethodSource("algorithmKeys")
    void parsedJwt_shouldBeImmutable(JwtAlgorithm algorithm, Jwt jwt, Key signKey, Key verifyKey) throws Exception {
        jwt.sign(signKey, algorithm);
        assertThrowsExactly(JwtStateException.class, ()->{
            jwt.getPayload().add("key","value");
        });
    }


    static Stream<Arguments> algorithmKeys(){
        return Stream.of(
                loadTokenAndKeys(JwtAlgorithm.HS256, true),
                loadTokenAndKeys(JwtAlgorithm.HS384, true),
                loadTokenAndKeys(JwtAlgorithm.HS512, true),
                loadTokenAndKeys(JwtAlgorithm.RS256, false),
                loadTokenAndKeys(JwtAlgorithm.RS384, false),
                loadTokenAndKeys(JwtAlgorithm.RS512, false)
        );
    }

    private static Arguments loadTokenAndKeys(JwtAlgorithm algorithm, boolean symmetric){
        Jwt unsignedJwt = TestUtils.createUnsignedJwt(algorithm);
        Key signKey;
        Key verifyKey;

        if(symmetric){
            signKey = TestUtils.loadKey(algorithm);
            verifyKey = signKey;
        }
        else {
            KeyPair pair = TestUtils.getKeyPair(algorithm);
            signKey = pair.getPrivate();
            verifyKey = pair.getPublic();
        }

        return Arguments.of(algorithm, unsignedJwt, signKey, verifyKey);
    }



    @Test
    void parsedJwt_shouldBeImmutable() {
        String token = TestUtils.loadToken(JwtAlgorithm.HS256);
        Key key = TestUtils.loadKey(JwtAlgorithm.HS256);
        Jwt jwt = Jwt.parse(token, key);

        assertThrowsExactly(JwtStateException.class,() -> {
            jwt.getPayload().add("key","value");
        });

        assertThrowsExactly(JwtStateException.class,() -> {
            jwt.getHeader().add("key","value");
        });

    }

    @Test
    void signedJwt_shouldBeImmutable(){
        Key key = TestUtils.loadKey(JwtAlgorithm.HS256);
        Jwt jwt = new Jwt(new JwtHeader(), new JwtPayload());
        jwt.sign(key, JwtAlgorithm.HS256);

        assertThrowsExactly(JwtStateException.class,()->{
            jwt.getPayload().add("key","value");
        });

        assertThrowsExactly(JwtStateException.class,()->{
            jwt.getHeader().add("key","value");
        });
    }

    @Test
    void get_shouldNotThrow_classCastException() throws Exception{
        JwtPayload payload = new JwtPayload();
        payload.add("my-list", List.of("one","two"));
        Jwt jwt = new Jwt(new JwtHeader(), payload);

        Key singKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        String token = jwt.sign(singKey,JwtAlgorithm.HS256);

        Jwt parsed = Jwt.parse(token, singKey);
        assertDoesNotThrow(
                ()-> {
                    List<String> myList = parsed.getPayload().get("my-list");
                }, "Failed to obtain List from JWT Payload");
    }

    @Test
    void get_shouldReturnList() throws Exception{
        Key singKey = KeyGenerator.getInstance("HmacSHA256").generateKey();

        JwtPayload payload = new JwtPayload();
        payload.add("my-list", List.of("one","two"));
        Jwt jwt = new Jwt(new JwtHeader(), payload);
        String token = jwt.sign(singKey,JwtAlgorithm.HS256);

        Jwt parsed = Jwt.parse(token, singKey);

        List<String> actualList = parsed.getPayload().get("my-list");

        assertNotNull(actualList);
        assertTrue(actualList.contains("one"));
        assertTrue(actualList.contains("two"));
    }

    @Test
    void get_shouldNotThrow_classCastException_forMap() throws Exception {
        JwtPayload payload = new JwtPayload();

        payload.add("my-map", Map.of(
                "key1", "value1",
                "key2", "value2"
        ));

        Jwt jwt = new Jwt(new JwtHeader(), payload);

        Key signKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        String token = jwt.sign(signKey, JwtAlgorithm.HS256);

        Jwt parsed = Jwt.parse(token, signKey);

        assertDoesNotThrow(
                () -> {
                    Map<String, String> myMap = parsed.getPayload().get("my-map");
                },
                "Failed to obtain Map from JWT Payload"
        );
    }

    @Test
    void get_shouldReturnMap() throws Exception {
        Key signKey = KeyGenerator.getInstance("HmacSHA256").generateKey();

        JwtPayload payload = new JwtPayload();
        payload.add("my-map", Map.of(
                "key1", "value1",
                "key2", "value2"
        ));

        Jwt jwt = new Jwt(new JwtHeader(), payload);
        String token = jwt.sign(signKey, JwtAlgorithm.HS256);

        Jwt parsed = Jwt.parse(token, signKey);

        Map<String, String> actualMap = parsed.getPayload().get("my-map");

        assertNotNull(actualMap);
        assertEquals(2, actualMap.size());
        assertEquals("value1", actualMap.get("key1"));
        assertEquals("value2", actualMap.get("key2"));
    }

    @ParameterizedTest
    @MethodSource("incorrectTokens")
    void missingHeader_shouldThrowMalformedException(Key verificationKey, String incorrectToken){
        assertThrows(JwtSecurityException.class,()->{
           Jwt.parse(incorrectToken, verificationKey);
        });
    }

    static Stream<Arguments> incorrectTokens(){
        Key key = TestUtils.loadKey(JwtAlgorithm.HS256);

        String missingHeader =
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0" +
                    ".HzrLVf79SNp1iZDWQ_d4eP5NccBzszMaXgME9KYZ8XY";

        String missingPayload =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
                    ".HzrLVf79SNp1iZDWQ_d4eP5NccBzszMaXgME9KYZ8XY";

        String missingSignature =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
                    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0";

        String malformedHeader =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ." +
                        "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
                        "HzrLVf79SNp1iZDWQ_d4eP5NccBzszMaXgME9KYZ8XY";

        String malformedPayload =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                        "eyJzdWIiOiIxMjM0NTY3ODkwI." +
                        "HzrLVf79SNp1iZDWQ_d4eP5NccBzszMaXgME9KYZ8XY";

        String malformedSignature =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                        "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
                        "HzrLVf79SNp1iZDWQ_d4eP5NccBzszMaXgME9KYZ8";

        // alg: none
        String noneAlgorithm =
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
                        "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
                        "HzrLVf79SNp1iZDWQ_d4eP5NccBzszMaXgME9KYZ8";

        // Algorithm confusion: HS256 header with an RSA public key used as HMAC key
        String algorithmConfusion =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                        "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
                        "SGVsbG9Xb3JsZA";

        // Empty signature
        String emptySignature =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                        "eyJzdWIiOiIxMjM0NTY3ODkwIn0.";

        // Wrong algorithm
        String wrongAlgorithm =
                "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
                        "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
                        "SGVsbG9Xb3JsZA";

        // Extra JWT segment
        String extraSegment =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                        "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
                        "SGVsbG9Xb3JsZA.extra";

        // Duplicate JSON header properties
        String duplicateAlgorithm =
                "eyJhbGciOiJIUzI1NiIsImFsZyI6Im5vbmUiLCJ0eXAiOiJKV1QifQ." +
                        "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
                        "SGVsbG9Xb3JsZA";

        String emptyPayload =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                        " .OWTbTWIFnHq365uyqlNDyhMiao9zr_eS-upovDcDEqw";

        String onlyDots = "..";


        return Stream.of(
                Arguments.of(key, missingHeader),
                Arguments.of(key, missingPayload),
                Arguments.of(key, missingSignature),
                Arguments.of(key, malformedHeader),
                Arguments.of(key, malformedPayload),
                Arguments.of(key, malformedSignature),
                Arguments.of(key, noneAlgorithm),
                Arguments.of(key, algorithmConfusion),
                Arguments.of(key, emptySignature),
                Arguments.of(key, wrongAlgorithm),
                Arguments.of(key, extraSegment),
                Arguments.of(key, duplicateAlgorithm),
                Arguments.of(key, emptyPayload),
                Arguments.of(key, onlyDots)
        );
    }


}
