package dev.ysdaeth.jwt;

import dev.ysdaeth.jwt.exception.*;
import org.junit.jupiter.api.Test;
import javax.crypto.KeyGenerator;
import static org.junit.jupiter.api.Assertions.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;

class JwtTest {

    @Test
    void parsedJwt_shouldBeImmutable() throws Exception {
        Key signKey = KeyGenerator.getInstance("HmacSHA256").generateKey();

        Jwt jwt = new Jwt(new JwtHeader(), new JwtPayload());
        String token = jwt.sign(signKey, JwtAlgorithm.HS256);
        Jwt immutableJwt = Jwt.parse(token,signKey);

        assertThrowsExactly(JwtStateException.class,()->{
            immutableJwt.getPayload().add("key","value");
        });
    }


    @Test
    void parsedJwt_shouldThrowException_whenReSigned() throws Exception{
        String token = JwtTestUtils.loadJwt("HS256.token");
        Key key = JwtTestUtils.loadSecretKey("HS256.key");
        Jwt jwt = Jwt.parse(token, key);

        assertThrowsExactly(JwtStateException.class,()->{
            jwt.sign(key,JwtAlgorithm.HS256);
        });
    }

    @Test
    void parsedJwt_shouldThrowException_whenSignKeyDoesNotMatch() throws Exception{
        String token = JwtTestUtils.loadJwt("HS256.token");
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        assertThrowsExactly(JwtSignatureException.class,()->{
            Jwt.parse(token, key);
        });
    }

    @Test
    void jwt_shouldThrowException_whenSignedTwice() throws Exception{
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jwt jwt = JwtTestUtils.createExpectedJwt("HS256", null);

        assertDoesNotThrow(()->{
            jwt.sign(key, JwtAlgorithm.HS256);
        });

        assertThrowsExactly(JwtStateException.class,()->{
            jwt.sign(key,JwtAlgorithm.HS256);
        });
    }

    @Test
    void jwtClaims_shouldThrowException_whenChangedAfterSign() throws Exception{
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jwt jwt = JwtTestUtils.createExpectedJwt("HS256", null);
        jwt.sign(key, JwtAlgorithm.HS256);
        JwtClaims headerClaims = jwt.getHeader().getClaims();
        JwtClaims payloadClaims = jwt.getPayload().getClaims();

        assertThrowsExactly(JwtStateException.class,()->{
            headerClaims.put("key","value");
        });

        assertThrowsExactly(JwtStateException.class,()->{
            payloadClaims.put("key","value");
        });
    }

    @Test
    void get_shouldReturnList() throws Exception{
        JwtPayload payload = new JwtPayload();
        payload.add("my-list", List.of("one","two"));
        Jwt jwt = new Jwt(new JwtHeader(), payload);

        Key singKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        String token = jwt.sign(singKey,JwtAlgorithm.HS256);

        Jwt parsed = Jwt.parse(token, singKey);
        assertDoesNotThrow(
                ()-> {
                    List<String> x = parsed.getPayload().get("my-list");
                }, "Failed to obtain List from JWT Payload");


        List<String> actualList = parsed.getPayload().get("my-list");
        assertTrue(actualList.contains("one"), "List from payload has missing elements");
        assertTrue(actualList.contains("two"), "List from payload has missing elements");
    }

    @Test
    void get_shouldThrow_ClassCastException() throws Exception {
        JwtPayload payload = new JwtPayload();
        payload.add("my-list", List.of("one","two"));
        Jwt jwt = new Jwt(new JwtHeader(), payload);

        Key singKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
        String token = jwt.sign(singKey,JwtAlgorithm.HS256);

        JwtPayload expectedPayload = Jwt.parse(token, singKey).getPayload();
        assertThrowsExactly(ClassCastException.class,()->{
            Boolean x = expectedPayload.get("my-list");
        });
    }

    // ALGORITHM TESTS

    @Test
    void sign_HS256_shouldSerializeToExpectedValue() throws Exception {
        Key keyHS256 = JwtTestUtils.loadSecretKey("HS256.key");
        String expectedSerialized = JwtTestUtils.loadJwt("HS256.token");

        Jwt jwt = JwtTestUtils.createExpectedJwt("HS256", null);
        String serialized = jwt.sign(keyHS256, JwtAlgorithm.HS256);
        assertEquals(expectedSerialized, serialized);
    }

    @Test
    void parse_HS256_shouldDeserializeClaims() throws Exception {
        Key keyHS256 = JwtTestUtils.loadSecretKey("HS256.key");
        String expectedSerialized = JwtTestUtils.loadJwt("HS256.token");
        String sigB64 = expectedSerialized.split("\\.")[2];

        Jwt expected = JwtTestUtils.createExpectedJwt("HS256", sigB64);
        Jwt actual = Jwt.parse(expectedSerialized, keyHS256);

        assertEquals(expected, actual,"JWT instances are not equal");
    }

    @Test
    void sign_RS256_shouldSerializeToExpectedToken() throws Exception {
        KeyPair keyPair = JwtTestUtils.loadKeyPair("RS256.pair");
        PrivateKey privateKey = keyPair.getPrivate();
        String expectedToken = JwtTestUtils.loadJwt("RS256.token");

        Jwt jwt = JwtTestUtils.createExpectedJwt("RS256", null);
        String actualToken = jwt.sign(privateKey, JwtAlgorithm.RS256);
        assertEquals(expectedToken, actualToken);
    }

    @Test
    void parse_RS256_shouldDeserializeClaims() throws Exception {
        String serialized = JwtTestUtils.loadJwt("RS256.token");
        String sigB64 = serialized.split("\\.")[2];

        Jwt expected = JwtTestUtils.createExpectedJwt("RS256", sigB64);
        KeyPair keyRS256 = JwtTestUtils.loadKeyPair("RS256.pair");
        PublicKey publicKey = keyRS256.getPublic();

        Jwt parsed = Jwt.parse(serialized, publicKey);

        assertEquals(expected, parsed,"JWT instances are not equal");
    }

    @Test
    void parse_shouldThrow_MalformedException(){
        String token = "invalid.token";
        Key key = null;

        assertThrowsExactly(JwtMalformedException.class,()->{
            Jwt.parse(token,key);
        });
    }

    @Test
    void parse_shouldThrow_ExpiredException() throws Exception{
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        JwtHeader header = new JwtHeader();
        JwtPayload payload = new JwtPayload();
        payload.setExpiresAt(Instant.now().minusSeconds(10));
        Jwt jwt = new Jwt(header, payload);

        String token = jwt.sign(key, JwtAlgorithm.HS256);

        assertThrowsExactly(JwtExpiredException.class,()->{
            Jwt.parse(token,key);
        });
    }

    @Test
    void parse_shouldThrow_UnsupportedException() throws Exception{
        String token = "eyJhbGciOiJ1bmtub3duIn0.e30.e30";
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        assertThrowsExactly(JwtUnsupportedException.class,()->{
            Jwt.parse(token,key);
        });
    }

    @Test
    void nullToken_shouldThrowMalformedException() throws Exception {
        String token = null;
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        assertThrowsExactly(JwtMalformedException.class,()->{
            Jwt.parse(token, key);
        });
    }
}