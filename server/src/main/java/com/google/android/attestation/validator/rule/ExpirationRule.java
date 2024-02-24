package com.google.android.attestation.validator.rule;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import com.google.android.attestation.validator.CertValidationException;

import com.google.android.attestation.validator.CertValidatorRule;

/**
 * check if certificate has expired or is not yet valid
 */
public class ExpirationRule implements CertValidatorRule {

	@Override
	public void validate(X509Certificate cert) throws CertValidationException {

		try {
			cert.checkValidity();
		} catch (CertificateExpiredException | CertificateNotYetValidException e) {
			throw new CertValidationException(e.getMessage(), e);
		}
	}

}
