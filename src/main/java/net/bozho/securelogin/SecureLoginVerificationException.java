package net.bozho.securelogin;

public class SecureLoginVerificationException extends Exception {
    private static final long serialVersionUID = 48074945112850945L;

    private SecureLoginVerificationFailure failure;
    
    public SecureLoginVerificationException(SecureLoginVerificationFailure failure) {
        this.failure = failure;
    }

    public SecureLoginVerificationFailure getFailure() {
        return failure;
    }
}
