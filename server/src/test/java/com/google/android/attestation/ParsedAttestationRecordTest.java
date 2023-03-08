/* Copyright 2019, The Android Open Source Project, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.android.attestation;

import static com.google.android.attestation.Constants.KM_KEY_PURPOSE_SIGN;
import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.android.attestation.AuthorizationList.UserAuthType;
import com.google.android.attestation.ParsedAttestationRecord.SecurityLevel;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for {@link ParsedAttestationRecord}. */
@RunWith(JUnit4.class)
public class ParsedAttestationRecordTest {
  public static final int EXPECTED_KEY_PURPOSE = KM_KEY_PURPOSE_SIGN;
  // The cert chains at the following paths were all generated on a Pixel 7 Pro, with
  // remotely-provisioned certificates.
  private static final String TEST_NORMAL_CERT_CHAIN_PATH =
      "src/test/resources/normal_cert_chain.pem";
  private static final String TEST_ATTEST_KEY_CERT_CHAIN_PATH =
      "src/test/resources/cert_chain_with_attest_keys.pem";
  private static final String TEST_FAKE_KEY_CERT_CHAIN_PATH =
      "src/test/resources/fake_cert_chain_with_attest_keys.pem";
  // The values specified in these expectation constants must match what's in the cert chains
  // mentioned above.
  private static final int EXPECTED_ATTESTATION_VERSION = 200;
  private static final SecurityLevel EXPECTED_ATTESTATION_SECURITY_LEVEL =
      SecurityLevel.TRUSTED_ENVIRONMENT;
  private static final int EXPECTED_KEYMASTER_VERSION = 200;
  private static final SecurityLevel EXPECTED_KEYMASTER_SECURITY_LEVEL =
      SecurityLevel.TRUSTED_ENVIRONMENT;
  private static final byte[] EXPECTED_ATTESTATION_CHALLENGE = "challenge".getBytes(UTF_8);
  private static final byte[] EXPECTED_UNIQUE_ID = "".getBytes(UTF_8);
  @Rule public ExpectedException fakeLeafException = ExpectedException.none();

  private ImmutableList<X509Certificate> loadCertificateChain(String filePath)
      throws FileNotFoundException, CertificateException {
    return CertificateFactory //
        .getInstance("X.509")
        .generateCertificates(new FileInputStream(filePath))
        .stream()
        .map(c -> (X509Certificate) c)
        .collect(ImmutableList.toImmutableList());
  }

  @Test
  public void testParseAttestationRecord() throws CertificateException, IOException {
    ParsedAttestationRecord attestationRecord =
        ParsedAttestationRecord.extractFreshestAttestation(
            loadCertificateChain(TEST_NORMAL_CERT_CHAIN_PATH));

    assertThat(attestationRecord.attestationVersion).isEqualTo(EXPECTED_ATTESTATION_VERSION);
    assertThat(attestationRecord.attestationSecurityLevel)
        .isEqualTo(EXPECTED_ATTESTATION_SECURITY_LEVEL);
    assertThat(attestationRecord.keymasterVersion).isEqualTo(EXPECTED_KEYMASTER_VERSION);
    assertThat(attestationRecord.keymasterSecurityLevel)
        .isEqualTo(EXPECTED_KEYMASTER_SECURITY_LEVEL);
    assertThat(attestationRecord.attestationChallenge).isEqualTo(EXPECTED_ATTESTATION_CHALLENGE);
    assertThat(attestationRecord.uniqueId).isEqualTo(EXPECTED_UNIQUE_ID);
    assertThat(attestationRecord.softwareEnforced).isNotNull();
    assertThat(attestationRecord.teeEnforced).isNotNull();
    Set<Integer> actual = attestationRecord.teeEnforced.purpose.orElse(Collections.emptySet());
    assertThat(actual).containsExactly(KM_KEY_PURPOSE_SIGN);
  }

  @Test
  public void testParseAttestationRecordWithAttestKeys() throws IOException, CertificateException {
    ParsedAttestationRecord attestationRecord =
        ParsedAttestationRecord.extractFreshestAttestation(
            loadCertificateChain(TEST_ATTEST_KEY_CERT_CHAIN_PATH));

    assertThat(attestationRecord.attestationVersion).isEqualTo(EXPECTED_ATTESTATION_VERSION);
    assertThat(attestationRecord.attestationSecurityLevel)
        .isEqualTo(EXPECTED_ATTESTATION_SECURITY_LEVEL);
    assertThat(attestationRecord.keymasterVersion).isEqualTo(EXPECTED_KEYMASTER_VERSION);
    assertThat(attestationRecord.keymasterSecurityLevel)
        .isEqualTo(EXPECTED_KEYMASTER_SECURITY_LEVEL);
    assertThat(attestationRecord.attestationChallenge).isEqualTo(EXPECTED_ATTESTATION_CHALLENGE);
    assertThat(attestationRecord.uniqueId).isEqualTo(EXPECTED_UNIQUE_ID);
    assertThat(attestationRecord.softwareEnforced).isNotNull();
    assertThat(attestationRecord.teeEnforced).isNotNull();
    Set<Integer> actual = attestationRecord.teeEnforced.purpose.orElse(Collections.emptySet());
    assertThat(actual).containsExactly(EXPECTED_KEY_PURPOSE);
  }

  @Test
  public void testParseAttestationRecordWithAttestKeysAndFakeLeaf() throws Exception {
    fakeLeafException.expect(IllegalArgumentException.class);
    fakeLeafException.expectMessage("Found non-ATTEST_KEY attestation after leaf.");
    ParsedAttestationRecord.extractFreshestAttestation(
        loadCertificateChain(TEST_FAKE_KEY_CERT_CHAIN_PATH));
  }

  @Test
  public void testCreateAndParseAttestationRecord() {
    ParsedAttestationRecord expected =
        ParsedAttestationRecord.create(
            /* attestationVersion= */ 2,
            /* attestationSecurityLevel= */ SecurityLevel.TRUSTED_ENVIRONMENT,
            /* keymasterVersion= */ 4,
            /* keymasterSecurityLevel= */ SecurityLevel.SOFTWARE,
            /* attestationChallenge= */ "abc".getBytes(UTF_8),
            /* uniqueId= */ "foodplease".getBytes(UTF_8),
            /* softwareEnforced= */ AuthorizationList.builder().build(),
            /* teeEnforced= */ AuthorizationList.builder()
                .setUserAuthType(ImmutableSet.of(UserAuthType.FINGERPRINT))
                .setAttestationIdBrand("free food".getBytes(UTF_8))
                .build());
    ASN1Sequence seq = expected.toAsn1Sequence();
    ParsedAttestationRecord actual = ParsedAttestationRecord.create(seq);
    assertThat(actual.attestationVersion).isEqualTo(expected.attestationVersion);
    assertThat(actual.attestationSecurityLevel).isEqualTo(expected.attestationSecurityLevel);
    assertThat(actual.keymasterVersion).isEqualTo(expected.keymasterVersion);
    assertThat(actual.keymasterSecurityLevel).isEqualTo(expected.keymasterSecurityLevel);
    assertThat(actual.attestationChallenge).isEqualTo(expected.attestationChallenge);
    assertThat(actual.uniqueId).isEqualTo(expected.uniqueId);
    assertThat(actual.teeEnforced.userAuthType).isEqualTo(expected.teeEnforced.userAuthType);
    assertThat(actual.teeEnforced.attestationIdBrand)
        .isEqualTo(expected.teeEnforced.attestationIdBrand);
  }
}
