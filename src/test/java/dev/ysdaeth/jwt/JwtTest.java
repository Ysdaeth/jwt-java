package dev.ysdaeth.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.security.Key;

class JwtTest {
    static Jwt expectedJwt;
    static final Key keyHS256 = JwtTestUtils.loadSymmetricKey("keyHS256.key");
    static final String expectedSerialized = JwtTestUtils.loadJwt("jwtHS256.txt");

    @BeforeEach
    void xd(){
        expectedJwt = JwtTestUtils.createExpectedUnsignedJwt();
    }


    @Test
    void serialize_shouldSerialize() throws Exception {
        Jwt jwt = JwtTestUtils.createExpectedUnsignedJwt();
        String serialized = jwt.sign(keyHS256, JwtAlgorithm.HS256);
        System.out.println(serialized);
        assertEquals(expectedSerialized, serialized);
    }

    @Test
    void parse_shouldDeserializeClaims() throws Exception {
        Jwt actual = Jwt.parse(expectedSerialized, keyHS256);
        Jwt expected = JwtTestUtils.createExpectedUnsignedJwt();

        Header actHeader = actual.getHeader();
        Header expHeader = expected.getHeader();

        Payload actPayload = actual.getPayload();
        Payload expPayload = expected.getPayload();

        assertEquals(expHeader, actHeader, "Header claims are not equal.");
        assertEquals(expPayload, actPayload,"Payload claims does not equal");
    }

}