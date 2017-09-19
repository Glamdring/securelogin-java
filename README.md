# securelogin-java
Java implementation of SecureLogin.pw verification

Usage:

```
String token = ... ; // obtain token from request
SecureLogin login = SecureLogin.verify(token, Options.create(ALLOWED_ORIGIN_DOMAINS));
String publicKey = login.getRawPublicKey();
// use public key to lookup the user in the database
```
