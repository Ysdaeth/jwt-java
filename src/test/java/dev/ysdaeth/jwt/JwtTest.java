package dev.ysdaeth.jwt;

import org.junit.jupiter.api.Test;
import javax.crypto.KeyGenerator;
import static org.junit.jupiter.api.Assertions.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

class JwtTest {

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
    void parsedJwt_shouldThrowException_whenKeyDoesNotMatch() throws Exception{
        String token = JwtTestUtils.loadJwt("HS256.token");
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        assertThrowsExactly(SecurityException.class,()->{
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
    void sign_RS256_shouldSerializeToExpectedValue() throws Exception {
        KeyPair keyPair = JwtTestUtils.loadKeyPair("RS256.pair");
        PrivateKey privateKey = keyPair.getPrivate();
        String expected = JwtTestUtils.loadJwt("RS256.token");

        Jwt jwt = JwtTestUtils.createExpectedJwt("RS256", null);
        String serialized = jwt.sign(privateKey, JwtAlgorithm.RS256);
        assertEquals(expected, serialized);
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

}