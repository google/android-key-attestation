package com.google.android.attestation.validator;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Performs X509 certificate validation. Add required list of validation rules  
 */
public class CertValidator implements CertValidatorRule {
	private List<CertValidatorRule> rules;

	private CertValidator(Builder builder) {
		this.rules = builder.rules;
	}

	@Override
	public void validate(X509Certificate cert) throws CertValidationException {
		for (CertValidatorRule validatorRule : rules) {
			validatorRule.validate(cert);
		}
	}

	public static final class Builder {

		private List<CertValidatorRule> rules;

		public Builder() {
			this.rules = new ArrayList<CertValidatorRule>();
		}

		public Builder addRule(CertValidatorRule validatorRule) {
			rules.add(validatorRule);
			return this;
		}

		public CertValidator build() {
			return new CertValidator(this);
		}
	}

}
