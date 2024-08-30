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
import static org.junit.Assert.assertThrows;

import com.google.android.attestation.AttestationApplicationId.AttestationPackageInfo;
import java.util.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for {@link AttestationApplicationId}. */
@RunWith(JUnit4.class)
public class AttestationApplicationIdTest {

  // Generated from certificate with RSA Algorithm and StrongBox Security Level
  private static final byte[] ATTESTATION_APPLICATION_ID =
          Base64.getDecoder().decode(
          "MIIBszGCAYswDAQHYW5kcm9pZAIBHTAZBBRjb20uYW5kcm9pZC5rZXljaGFpbgIBHTAZBBRjb20uYW5kcm9p"
              + "ZC5zZXR0aW5ncwIBHTAZBBRjb20ucXRpLmRpYWdzZXJ2aWNlcwIBHTAaBBVjb20uYW5kcm9pZC5keW"
              + "5zeXN0ZW0CAR0wHQQYY29tLmFuZHJvaWQuaW5wdXRkZXZpY2VzAgEdMB8EGmNvbS5hbmRyb2lkLmxv"
              + "Y2FsdHJhbnNwb3J0AgEdMB8EGmNvbS5hbmRyb2lkLmxvY2F0aW9uLmZ1c2VkAgEdMB8EGmNvbS5hbm"
              + "Ryb2lkLnNlcnZlci50ZWxlY29tAgEdMCAEG2NvbS5hbmRyb2lkLndhbGxwYXBlcmJhY2t1cAIBHTAh"
              + "BBxjb20uZ29vZ2xlLlNTUmVzdGFydERldGVjdG9yAgEdMCIEHWNvbS5nb29nbGUuYW5kcm9pZC5oaW"
              + "RkZW5tZW51AgEBMCMEHmNvbS5hbmRyb2lkLnByb3ZpZGVycy5zZXR0aW5ncwIBHTEiBCAwGqPLCBE0"
              + "UBxF8UIqvGbCQiT9Xe1f3I8X5pcXb9hmqg==");

  private static final AttestationApplicationId EXPECTED_ATTESTATION_APPLICATION_ID =
      AttestationApplicationId.builder()
          .addPackageInfo(
              AttestationPackageInfo.builder().setPackageName("android").setVersion(29L).build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.android.keychain")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.android.settings")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.qti.diagservices")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.android.dynsystem")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.android.inputdevices")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.android.localtransport")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.android.location.fused")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.android.server.telecom")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.android.wallpaperbackup")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.google.SSRestartDetector")
                  .setVersion(29L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.google.android.hiddenmenu")
                  .setVersion(1L)
                  .build())
          .addPackageInfo(
              AttestationPackageInfo.builder()
                  .setPackageName("com.android.providers.settings")
                  .setVersion(29L)
                  .build())
          .addSignatureDigest(
              Base64.getDecoder().decode("MBqjywgRNFAcRfFCKrxmwkIk/V3tX9yPF+aXF2/YZqo="))
          .build();

  @Test
  public void testCreateAttestationApplicationId() {
    AttestationApplicationId attestationApplicationId =
        AttestationApplicationId.createAttestationApplicationId(ATTESTATION_APPLICATION_ID);
    assertThat(attestationApplicationId).isEqualTo(EXPECTED_ATTESTATION_APPLICATION_ID);
  }

  @Test
  public void createAttestationApplicationId_nullOrInvalidInput_throwsException() {
    assertThrows(
        NullPointerException.class,
        () -> AttestationApplicationId.createAttestationApplicationId(null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AttestationApplicationId.createAttestationApplicationId(
                "Invalid DEROctet String".getBytes(UTF_8)));
  }

  @Test
  public void testBuildAttestationApplicationId() {
    byte[] encoded = EXPECTED_ATTESTATION_APPLICATION_ID.getEncoded();

    assertThat(encoded).isEqualTo(ATTESTATION_APPLICATION_ID);
  }
}
