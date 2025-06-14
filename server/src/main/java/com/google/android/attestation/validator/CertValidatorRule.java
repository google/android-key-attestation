package com.google.android.attestation.validator;

import java.security.cert.X509Certificate;

/**
 * Identify a validation rule   
 */
public interface CertValidatorRule {
	void validate(X509Certificate cert) throws CertValidationException;
}
