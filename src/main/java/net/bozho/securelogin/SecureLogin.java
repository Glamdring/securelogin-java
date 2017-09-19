package net.bozho.securelogin;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class SecureLogin {

    private static final int EXPIRATION_TOLERANCE_SECONDS = 86400;
    private static final String HMAC_ALGORITHM = "HmacSHA512";
    private String provider;
    private String client;
    private Map<String, List<String>> scope;
    private LocalDateTime expiresAt;
    private String email;
    private PublicKey publicKey;
    private String secret;
    
    static {
        Security.addProvider(new EdDSASecurityProvider());
    }
    
    // spec https://github.com/sakurity/securelogin-spec/blob/master/index.md
    
    public static SecureLogin verify(String token, Options options) throws SecureLoginVerificationException {
        String[] args = splitAndDecode(token);
        String message = args[0];
        String signatures = args[1];
        String authKeys = args[2];
        String email = args[3];
        
        String[] parsedSignatures = splitAndDecode(signatures);
        String signature = parsedSignatures[0];
        String hmacSignature = parsedSignatures[1];
        
        String[] authKeysParsed = splitAndDecode(authKeys);
        String publicKeyRaw = options.getPublicKey() != null ? options.getPublicKey() : authKeysParsed[0];
        String hmacSecret = options.getSecret() != null ? options.getSecret() : authKeysParsed[1];

        PublicKey publicKey = extractPublicKey(publicKeyRaw);
        if (!verifySignature(message, signature, publicKey)) {
            throw new SecureLoginVerificationException(SecureLoginVerificationFailure.INVALID_SIGNATURE);
        }
        
        if (options.isPerformHmacCheck() && !verifyHmac(message, hmacSignature, hmacSecret)) {
            throw new SecureLoginVerificationException(SecureLoginVerificationFailure.INVALID_HMAC);
        }
        
        String[] messageParsed = splitAndDecode(message);
        String provider = messageParsed[0];
        String client = messageParsed[1];
        Map<String, List<String>> scope = splitQuery(messageParsed[2]);
        LocalDateTime expiresAt = LocalDateTime.ofInstant(
                Instant.ofEpochSecond(Long.parseLong(messageParsed[3])), ZoneId.of("UTC"));
        
        if (!options.getOrigins().contains(provider)) {
            throw new SecureLoginVerificationException(SecureLoginVerificationFailure.INVALID_PROVIDER);
        }
        
        if (!options.getOrigins().contains(client) && !options.isConnect()) { // connect is an OAuth replacement, check spec
            throw new SecureLoginVerificationException(SecureLoginVerificationFailure.INVALID_CLIENT);
        }

        if (options.isPerformExpirationCheck()
                && expiresAt.plusSeconds(EXPIRATION_TOLERANCE_SECONDS).isBefore(LocalDateTime.now())) {
            throw new SecureLoginVerificationException(SecureLoginVerificationFailure.EXPIRED_TOKEN);
        }
        
        verifyScope(options, scope);
        
        SecureLogin secureLogin = new SecureLogin();
        secureLogin.provider = provider;
        secureLogin.client = client;
        secureLogin.scope = scope;
        secureLogin.expiresAt = expiresAt;
        secureLogin.email = email;
        secureLogin.publicKey = publicKey;
        secureLogin.secret = hmacSecret;
        
        return secureLogin;
    }

    private static void verifyScope(Options options, Map<String, List<String>> scope)
            throws SecureLoginVerificationException {
        if (options.isPasswordChange()) {
            boolean properScope = scope.get("mode").contains("change") && scope.containsKey("to") && scope.size() == 2;
            if (!properScope) {
                throw new SecureLoginVerificationException(SecureLoginVerificationFailure.NOT_CHANGE_TOKEN_MODE);
            }
        } else if (!scope.isEmpty() && !scope.equals(options.getScope())){
            throw new SecureLoginVerificationException(SecureLoginVerificationFailure.INVALID_SCOPE);
        }
    }

    private static PublicKey extractPublicKey(String publicKeyRaw) {
        try {
            KeyFactory factory = KeyFactory.getInstance(EdDSAKey.KEY_ALGORITHM);
            PublicKey publicKey = factory.generatePublic(new EdDSAPublicKeySpec(
                    Base64.getDecoder().decode(publicKeyRaw), EdDSANamedCurveTable.getByName("Ed25519")));
            return publicKey;
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    private static boolean verifySignature(String message, String signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance(EdDSAEngine.SIGNATURE_ALGORITHM);
            sig.initVerify(publicKey);
            sig.update(message.getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.getDecoder().decode(signature));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean verifyHmac(String message, String hmacSignature, String hmacSecret) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(Base64.getDecoder().decode(hmacSecret), HMAC_ALGORITHM);
            mac.init(secretKey);
            byte[] actualSignature = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Arrays.equals(Arrays.copyOf(actualSignature, 32), Base64.getDecoder().decode(hmacSignature));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    
    private static String[] splitAndDecode(String token) {
        String[] elements = token.split(",");
        for (int i = 0; i < elements.length; i ++) {
            try {
                // replacing + with its encoded version - a hacky way to overcome the difference
                // in url decoding implementstions of Ruby and Java, which has crept into the securelogin spec
                elements[i] = URLDecoder.decode(elements[i].replace("+", "%2B"), StandardCharsets.UTF_8.name());
            } catch (UnsupportedEncodingException e) {
                throw new AssertionError(e);
            }
        }
        return elements;
    }
    
    private static Map<String, List<String>> splitQuery(String queryString) {
        if (queryString == null || queryString.isEmpty()) {
            return Collections.emptyMap();
        }
        return Arrays.stream(queryString.split("&"))
                .map(SecureLogin::splitQueryParameter)
                .collect(Collectors.groupingBy(SimpleImmutableEntry::getKey, 
                        LinkedHashMap::new, 
                        Collectors.mapping(Map.Entry::getValue, Collectors.toList())));
    }
    
    private static SimpleImmutableEntry<String, String> splitQueryParameter(String it) {
        final int idx = it.indexOf("=");
        final String key = idx > 0 ? it.substring(0, idx) : it;
        final String value = idx > 0 && it.length() > idx + 1 ? it.substring(idx + 1) : null;
        return new SimpleImmutableEntry<>(key, value);
    }
    
    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getClient() {
        return client;
    }

    public void setClient(String client) {
        this.client = client;
    }

    public Map<String, List<String>> getScope() {
        return scope;
    }

    public void setScope(Map<String, List<String>> scope) {
        this.scope = scope;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }


    
    @Override
    public String toString() {
        return "SecureLogin [provider=" + provider + ", client=" + client + ", scope=" + scope + ", expiresAt="
                + expiresAt + ", email=" + email + ", publicKey=" + publicKey + ", secret=" + secret + "]";
    }
}
