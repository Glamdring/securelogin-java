package net.bozho.securelogin;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Options {
    private String publicKey;
    private String secret;
    private Set<String> origins;
    private Map<String, List<String>> scope;
    private boolean performHmacCheck;
    private boolean connect;
    private boolean passwordChange;
    private boolean performExpirationCheck;
    
    private Options() {
    }
    
    public static Options create(Set<String> origins) {
        Options options = new Options();
        options.origins = origins;
        options.performExpirationCheck = true;
        return options;
    }
    public static Options create(String origin) {
        return create(Collections.singleton(origin));
    }
    public String getPublicKey() {
        return publicKey;
    }
    public Options setPublicKey(String publicKey) {
        this.publicKey = publicKey;
        return this;
    }
    public String getSecret() {
        return secret;
    }

    public Options setSecret(String secret) {
        this.secret = secret;
        return this;
    }

    public Set<String> getOrigins() {
        return origins;
    }

    public boolean isPerformHmacCheck() {
        return performHmacCheck;
    }

    public Options setPerformHmacCheck(boolean performHmacCheck) {
        this.performHmacCheck = performHmacCheck;
        return this;
    }

    public boolean isConnect() {
        return connect;
    }

    public Options setConnect(boolean connect) {
        this.connect = connect;
        return this;
    }

    public boolean isPasswordChange() {
        return passwordChange;
    }

    public Options setPasswordChange(boolean passwordChange) {
        this.passwordChange = passwordChange;
        return this;
    }

    public Map<String, List<String>> getScope() {
        return scope;
    }

    public Options setScope(Map<String, List<String>> scope) {
        this.scope = scope;
        return this;
    }

    public boolean isPerformExpirationCheck() {
        return performExpirationCheck;
    }

    public Options setPerformExpirationCheck(boolean performExpirationCheck) {
        this.performExpirationCheck = performExpirationCheck;
        return this;
    }
    
}