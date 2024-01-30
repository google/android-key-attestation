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
import static com.google.common.truth.Truth8.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.android.attestation.RootOfTrust.VerifiedBootState;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.util.Base64;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Test for {@link RootOfTrust}. */
@RunWith(JUnit4.class)
public class RootOfTrustTest {

  // Generated from certificate with EC Algorithm and StrongBox Security Level
  private static final String ROOT_OF_TRUST =
      "MEoEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCByjbEnTx8c8Vcd5DgLBIpVSsSjgOdvU1UI"
          + "NSkISpN4AQ==";
  private static final int ATTESTATION_VERSION = 3;

  private static final ByteString EXPECTED_VERIFIED_BOOT_KEY =
      ByteString.copyFrom(Base64.getDecoder().decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
  private static final boolean EXPECTED_DEVICE_LOCKED = false;
  private static final VerifiedBootState EXPECTED_VERIFIED_BOOT_STATE =
      VerifiedBootState.UNVERIFIED;
  private static final ByteString EXPECTED_VERIFIED_BOOT_HASH =
      ByteString.copyFrom(Base64.getDecoder().decode("co2xJ08fHPFXHeQ4CwSKVUrEo4Dnb1NVCDUpCEqTeAE="));

  private static ASN1Sequence getRootOfTrustSequence(String rootOfTrustB64) throws IOException {
    byte[] rootOfTrustBytes = Base64.getDecoder().decode(rootOfTrustB64);
    return (ASN1Sequence) ASN1Sequence.fromByteArray(rootOfTrustBytes);
  }

  @Test
  public void testCreateRootOfTrust() throws IOException {
    ASN1Sequence rootOfTrustSequence = getRootOfTrustSequence(ROOT_OF_TRUST);
    RootOfTrust rootOfTrust =
        RootOfTrust.createRootOfTrust(rootOfTrustSequence, ATTESTATION_VERSION);

    assertThat(rootOfTrust).isNotNull();
    assertThat(rootOfTrust.verifiedBootKey).isEqualTo(EXPECTED_VERIFIED_BOOT_KEY);
    assertThat(rootOfTrust.deviceLocked).isEqualTo(EXPECTED_DEVICE_LOCKED);
    assertThat(rootOfTrust.verifiedBootState).isEqualTo(EXPECTED_VERIFIED_BOOT_STATE);
    assertThat(rootOfTrust.verifiedBootHash).hasValue(EXPECTED_VERIFIED_BOOT_HASH);
  }

  @Test
  public void testCreateEmptyRootOfTrust() {
    assertThrows(
        NullPointerException.class, () -> RootOfTrust.createRootOfTrust(null, ATTESTATION_VERSION));
  }
}
