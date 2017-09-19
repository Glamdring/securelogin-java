package net.bozho.securelogin;

public enum SecureLoginVerificationFailure {
    INVALID_SIGNATURE, INVALID_HMAC, INVALID_PROVIDER, INVALID_CLIENT, EXPIRED_TOKEN, INVALID_SCOPE, NOT_CHANGE_TOKEN_MODE
}
