# How to use
Library is really simple to use, methods names are created to be self-explanatory.
All classes come from 
```java
import dev.ysdaeth.jwt;
```

## JSON Web Token

### Create Jwt instance
You can create instance. Constructor requires Header and Payload

```java
Header header = new Header();
header.setKeyId("my-key");
header.add("key","value");

Payload payload = new Payload();
payload.setIssuer("me");
payload.setSubject("you");
payload.setExpiresAt(expiresAt);
payload.addBytes("bytes", new byte[]{1,2,3});
payload.add("iLikeCats", true);

Jwt jwt = new Jwt(header, payload);
```
### Create signed token
Once sign is created, it cannot be created once again from the same instance. 
Furthermore, changing header or payload claims will throw JwtStateException.

```java
JwtAlgorithm algorithm = JwtAlgorithm.HS256;
Key signKey = ...;
String token = jwt.sign(signKey, algorithm);
```

### Parsing JWT with key
When key does not match the signature, the SecurityException is thrown, and instance is not created.

```java
import dev.ysdaeth.jwt.Header;

String jsonWebToken = ...;
Key key = ...;
Jwt jwt = Jwt.parse(jsonWebToken, key);

Payload payload = jwt.getPayload();
Header header = jwt.getHeader();

String subject = payload.getSubject();
```

### Parsing JWT with KeyLocator
KeyLocator is a functional interface, it is used to supply the keyId from the header.

```java
import dev.ysdaeth.jwt.Jwt;

class MyKeyLocator implements KeyLocator {
    private Key key = ...;

    public Key findKey(String keyId) {
        if ("my-key".equals(keyId)) return key;
        return null;
    }
}

String jsonWebToken = ...;
Jwt jwt = Jwt.parse(jsonWebToken, new MyKeyLocator()); //or lambda expression
```