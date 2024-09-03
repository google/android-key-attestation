package com.google.android.attestation.validator;

/**
 * This exception is thrown if the certificate fails any of the validation rule     
 */
public class CertValidationException extends Exception {

	private static final long serialVersionUID = 1L;

    public CertValidationException(String msg) {
        super(msg);
    }

    public CertValidationException(String message, Throwable cause) {
        super(message, cause);
    }	
}
