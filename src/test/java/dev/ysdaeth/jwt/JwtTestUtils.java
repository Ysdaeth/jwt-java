package dev.ysdaeth.jwt;

import org.junit.jupiter.params.shadow.de.siegmar.fastcsv.util.Nullable;

import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

public class JwtTestUtils {


    static Key loadSecretKey(String filename){
        String keyAlg;
        byte[] keyBytes;
        try{
            Path path = Path.of("src","test", "resources", "jwt", filename);
            String[] content = Files.readString(path).split("\\n");
            keyAlg = content[0].trim();
            String base64 = content[1].trim();
            keyBytes = Base64.getUrlDecoder().decode(base64);
        }catch (Exception e){
            throw new RuntimeException("failed to load key '" + filename+"' " + e.getMessage(), e);
        }
        return new SecretKeySpec(keyBytes, keyAlg);
    }

    static KeyPair loadKeyPair(String filename){
        try{
            Path path = Path.of("src","test", "resources", "jwt", filename);
            String[] content = Files.readString(path).split("\\n");
            String keyAlg = content[0].trim();

            KeyFactory keyFactory = KeyFactory.getInstance(keyAlg);
            byte[] pv = Base64.getMimeDecoder().decode(content[2].trim());
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(pv);
            PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);

            byte[] pub = Base64.getMimeDecoder().decode(content[5].trim());
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(pub);
            PublicKey pubKey = keyFactory.generatePublic(publicSpec);
            return new KeyPair(pubKey, privateKey);

        }catch (Exception e){
            throw new RuntimeException("failed to load key '" + filename+"' " + e.getMessage(), e);
        }
    }

    static String loadJwt(String filename){
        Path path = Path.of("src","test", "resources", "jwt", filename);
        try{
            return Files.readString(path).trim();
        }catch (Exception e){
               throw new RuntimeException("Failed to read file "+ filename +" . " + e.getMessage(), e);
        }
    }

    static Jwt createExpectedJwt(String algorithm, @Nullable String signatureBase64){
        JwtHeader header = new JwtHeader().setKeyId("my-key");
        header.add("customHeader","custom-header");
        header.add("number", 1);
        header.setType("JWT");
        header.setAlgorithm(algorithm);

        Instant issuedAt = Instant.parse("2026-05-30T14:00:00Z");
        Instant expiresAt = Instant.parse("2026-05-30T14:15:00Z");

        JwtPayload payload = new JwtPayload();
        payload.setIssuer("me");
        payload.setSubject("you");
        payload.setJwtId("jwtId");
        payload.setIssuedAt(issuedAt);
        payload.setExpiresAt(expiresAt);
        payload.addBytes("bytes", new byte[]{1,2,3});
        payload.add("iLikeCats", true);


        Jwt jwt = new Jwt(header, payload);

        if(signatureBase64 != null){
            byte[] sigBytes = JwtBytesPolicy.bytesFromBase64(signatureBase64);
            JwtSignature jwtSignature = new JwtSignature(sigBytes);
            jwt.setSignature(jwtSignature);
        }
        return jwt;
    }


}
