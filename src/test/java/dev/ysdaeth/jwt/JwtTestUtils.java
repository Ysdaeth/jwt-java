package dev.ysdaeth.jwt;

import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.time.Instant;
import java.util.Base64;

public class JwtTestUtils {

    static Key loadSymmetricKey(String filename){
        String keyAlg;
        byte[] keyBytes;
        try{
            Path path = Path.of("src","test", "resources", "jwt", filename);
            String[] content = Files.readString(path).split("\\n");
            keyAlg = content[0];
            String base64 = content[1];
            keyBytes = Base64.getUrlDecoder().decode(base64);
        }catch (Exception e){
            throw new RuntimeException("failed to read test key for JWT HS256. " + e.getMessage(), e);
        }
        return new SecretKeySpec(keyBytes, keyAlg);
    }

    static String loadJwt(String filename){
        Path path = Path.of("src","test", "resources", "jwt", filename);
        try{
            return Files.readString(path).trim();
        }catch (Exception e){
               throw new RuntimeException("Failed to read file "+ filename +" . " + e.getMessage(), e);
        }
    }

    static Jwt createExpectedUnsignedJwt(){
        Header header = new Header().setKeyId("my-key");
        header.add("customHeader","custom-header");
        header.add("number", 1);
        header.setType("JWT");
        header.setAlgorithm("HS256");

        Instant issuedAt = Instant.parse("2026-05-30T14:00:00Z");
        Instant expiresAt = Instant.parse("2026-05-30T14:15:00Z");

        Payload payload = new Payload();
        payload.setIssuer("me");
        payload.setSubject("you");
        payload.setJwtId("jwtId");
        payload.setIssuedAt(issuedAt);
        payload.setExpiresAt(expiresAt);
        payload.addBytes("bytes", new byte[]{1,2,3});
        payload.add("iLikeCats", true);

        return new Jwt(header, payload);
    }


}
