# How to use
Library is really simple to use, methods names are created to be self-explanatory, 
so this tutorial will not be that much detailed.

First lets add a dependency.  
```xml
<dependency>
    <groupId>dev.ysdaeth.jwt</groupId>
    <artifactId>jwt-java</artifactId>
    <version>x.y.z</version>
</dependency>
```

## JSON Web Token

### Create Jwt instance
You can create instance. Constructor requires Header and Payload

```java
JwtHeader header = new JwtHeader();
header.setKeyId("my-key");
header.add("key","value");

JwtPayload payload = new JwtPayload();
payload.setIssuer("me");
payload.setSubject("you");
payload.setExpiresAt(expiresAt);
payload.addBytes("bytes", new byte[]{1,2,3});
payload.add("iLikeCats", true);

Jwt jwt = new Jwt(header, payload);
```

### Create signed token
Once signature is created, it cannot be created once again from the same instance. 
Furthermore, changing header or payload claims will throw JwtStateException.

```java
JwtAlgorithm algorithm = JwtAlgorithm.HS256;
Key signKey = ...;
String token = jwt.sign(signKey, algorithm);
```

### Parsing JWT with key
When key does not match the signature, the SecurityException is thrown, and instance is not created. 
Also, it is not possible to change claims of the parsed Jwt instance, doing so will throw an exception.

```java
String jsonWebToken = ...;
Key key = ...;
 
Jwt jwt = Jwt.parse(jsonWebToken, key); // if key is invalid throws SecurityException

JwtPayload payload = jwt.getPayload();
JwtHeader header = jwt.getHeader();

String subject = payload.getSubject();
```

### Parsing JWT with KeyLocator
KeyLocator is a **functional interface**, it is used to supply the unsafe header (not verified) to access required fields 
like key id or public key location. 

```java
class MyKeyLocator implements KeyLocator {
    private Key key = ...;

    public Key findKey(JwtHeader unsafeHeader) {
        String keyId = unsafeHeader.getKeyId();
        if("keyId".equals(keyId)) return key;
        return null;
    }
}
```
Now lets use our KeyLocator to verify and parse Jwt.
```java
String jsonWebToken = ...;
Jwt jwt = Jwt.parse(jsonWebToken, new MyKeyLocator()); //or lambda expression
```

## Working Example
Below is full working example, that includes Signing and parsing JSON Web Token with and without KeyLocator

```java
import dev.ysdaeth.jwt.*;
import dev.ysdaeth.jwt.exception.JwtStateException;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.time.Instant;

public class Example {

    void runExample() throws Exception {
        Key key = MyKeyLocator.key;

        JwtHeader header = new JwtHeader();
        header.setKeyId("keyId");
        header.add("customHeader", "value");

        JwtPayload payload = new JwtPayload();
        payload.setExpiresAt(Instant.now().plusSeconds(300));
        payload.setIssuer("Ysdaeth");
        payload.setSubject("You");
        payload.add("role", "DEVELOPER");
        payload.add("bans", 0);
        payload.add("isBanned", false);

        Jwt jwt = new Jwt(header, payload);
        String jsonWebToken = jwt.sign(key, JwtAlgorithm.HS256);

        System.out.println("=== TOKEN ===");
        System.out.println(jsonWebToken);
        System.out.println("=== TOKEN ===");

        try {
            jwt.getPayload().add("role", "ADMIN");
        } catch (JwtStateException e) {
            System.out.println(
                    "You must not modify jwt claims, when it's already signed. " + e.getMessage());
        }

        Jwt parsedJwt = Jwt.parse(jsonWebToken, key);
        JwtPayload parsedPayload = parsedJwt.getPayload();
        String subject = parsedPayload.getSubject();
        System.out.println("Hello, " + subject);

        Jwt parsedWithKeyLocator = Jwt.parse(jsonWebToken, new MyKeyLocator());
        String subject2 = parsedWithKeyLocator.getPayload().getSubject();

        System.out.println("Hello, " + subject2 + ". Key locator works!");
    }

    private static class MyKeyLocator implements KeyLocator {
        public static Key key = generateKey();

        @Override
        public Key findKey(JwtHeader unsafeHeader) {
            String keyId = unsafeHeader.getKeyId();
            if ("keyId".equals(keyId)) return key;
            return null;
        }

        static Key generateKey() {
            byte[] keyBytes = new byte[32];
            new SecureRandom().nextBytes(keyBytes);
            return new SecretKeySpec(keyBytes, "HmacSHA256");
        }

    }
}

```