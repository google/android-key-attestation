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

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.android.attestation.AttestationApplicationId.AttestationPackageInfo;
import com.google.common.collect.ImmutableList;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for {@link AttestationApplicationId}. */
@RunWith(JUnit4.class)
public class AttestationApplicationIdTest {

  // Generated from certificate with RSA Algorithm and StrongBox Security Level
  private static final DEROctetString ATTESTATION_APPLICATION_ID =
      new DEROctetString(
          Base64.decode(
              "MIIBszGCAYswDAQHYW5kcm9pZAIBHTAZBBRjb20uYW5kcm9pZC5rZXljaGFpbgIBHTAZBBRjb20uYW5kcm9p"
                  + "ZC5zZXR0aW5ncwIBHTAZBBRjb20ucXRpLmRpYWdzZXJ2aWNlcwIBHTAaBBVjb20uYW5kcm9pZC5keW"
                  + "5zeXN0ZW0CAR0wHQQYY29tLmFuZHJvaWQuaW5wdXRkZXZpY2VzAgEdMB8EGmNvbS5hbmRyb2lkLmxv"
                  + "Y2FsdHJhbnNwb3J0AgEdMB8EGmNvbS5hbmRyb2lkLmxvY2F0aW9uLmZ1c2VkAgEdMB8EGmNvbS5hbm"
                  + "Ryb2lkLnNlcnZlci50ZWxlY29tAgEdMCAEG2NvbS5hbmRyb2lkLndhbGxwYXBlcmJhY2t1cAIBHTAh"
                  + "BBxjb20uZ29vZ2xlLlNTUmVzdGFydERldGVjdG9yAgEdMCIEHWNvbS5nb29nbGUuYW5kcm9pZC5oaW"
                  + "RkZW5tZW51AgEBMCMEHmNvbS5hbmRyb2lkLnByb3ZpZGVycy5zZXR0aW5ncwIBHTEiBCAwGqPLCBE0"
                  + "UBxF8UIqvGbCQiT9Xe1f3I8X5pcXb9hmqg=="));

  private static final ImmutableList<AttestationPackageInfo> EXPECTED_PACKAGE_INFOS =
      ImmutableList.of(
          new AttestationPackageInfo("android", 29L),
          new AttestationPackageInfo("com.android.keychain", 29L),
          new AttestationPackageInfo("com.android.settings", 29L),
          new AttestationPackageInfo("com.qti.diagservices", 29L),
          new AttestationPackageInfo("com.android.dynsystem", 29L),
          new AttestationPackageInfo("com.android.inputdevices", 29L),
          new AttestationPackageInfo("com.android.localtransport", 29L),
          new AttestationPackageInfo("com.android.location.fused", 29L),
          new AttestationPackageInfo("com.android.server.telecom", 29L),
          new AttestationPackageInfo("com.android.wallpaperbackup", 29L),
          new AttestationPackageInfo("com.google.SSRestartDetector", 29L),
          new AttestationPackageInfo("com.google.android.hiddenmenu", 1L),
          new AttestationPackageInfo("com.android.providers.settings", 29L));
  private static final ImmutableList<byte[]> EXPECTED_SIGNATURE_DIGESTS =
      ImmutableList.of(Base64.decode("MBqjywgRNFAcRfFCKrxmwkIk/V3tX9yPF+aXF2/YZqo=\n"));

  private static final AttestationApplicationId EXPECTED_ATTESTATION_APPLICATION_ID =
      new AttestationApplicationId(EXPECTED_PACKAGE_INFOS, EXPECTED_SIGNATURE_DIGESTS);

  @Test
  public void testCreateAttestationApplicationId() {
    AttestationApplicationId attestationApplicationId =
        AttestationApplicationId.createAttestationApplicationId(ATTESTATION_APPLICATION_ID);
    assertThat(attestationApplicationId).isEqualTo(EXPECTED_ATTESTATION_APPLICATION_ID);
  }

  @Test
  public void testCreateEmptyAttestationApplicationIdFromEmptyOrInvalidInput() {
    assertThat(AttestationApplicationId.createAttestationApplicationId(null)).isNull();
    assertThat(
            AttestationApplicationId.createAttestationApplicationId(
                new DEROctetString("Invalid DEROctet String".getBytes(UTF_8))))
        .isNull();
  }

  @Test
  public void testEquals() {
    AttestationApplicationId attestationApplicationId =
        AttestationApplicationId.createAttestationApplicationId(ATTESTATION_APPLICATION_ID);
    AttestationApplicationId emptyAttestationApplicationId =
        new AttestationApplicationId(ImmutableList.of(), ImmutableList.of());

    assertThat(attestationApplicationId.equals(EXPECTED_ATTESTATION_APPLICATION_ID)).isTrue();
    assertThat(EXPECTED_ATTESTATION_APPLICATION_ID.equals(attestationApplicationId)).isTrue();

    assertThat(attestationApplicationId.equals(emptyAttestationApplicationId)).isFalse();
    assertThat(emptyAttestationApplicationId.equals(attestationApplicationId)).isFalse();
  }

  @Test
  public void testEqualObjectsHaveEqualHashCodes() {
    AttestationApplicationId attestationApplicationId =
        AttestationApplicationId.createAttestationApplicationId(ATTESTATION_APPLICATION_ID);

    assertThat(attestationApplicationId.equals(EXPECTED_ATTESTATION_APPLICATION_ID)).isTrue();
    assertThat(attestationApplicationId.hashCode())
        .isEqualTo(EXPECTED_ATTESTATION_APPLICATION_ID.hashCode());
  }
}
