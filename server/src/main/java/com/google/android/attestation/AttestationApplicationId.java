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

import static com.google.android.attestation.Constants.ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_PACKAGE_INFO_VERSION_INDEX;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.common.collect.Streams.stream;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

/**
 * This data structure reflects the Android platform's belief as to which apps are allowed to use
 * the secret key material under attestation. The ID can comprise multiple packages if and only if
 * multiple packages share the same UID.
 *
 * <p>The Attestation Application ID data from KeyMint will not exceed 1K bytes.
 */
@AutoValue
@Immutable
public abstract class AttestationApplicationId {
  public abstract ImmutableList<AttestationPackageInfo> packageInfos();

  public abstract ImmutableList<ByteString> signatureDigests();

  public static AttestationApplicationId create(
      List<AttestationPackageInfo> packageInfos, List<ByteString> signatureDigests) {
    return new AutoValue_AttestationApplicationId(
        ImmutableList.copyOf(packageInfos), ImmutableList.copyOf(signatureDigests));
  }

  static AttestationApplicationId createAttestationApplicationId(byte[] attestationApplicationId) {
    ASN1Sequence attestationApplicationIdSequence =
        ASN1Sequence.getInstance(attestationApplicationId);
    ASN1Set attestationPackageInfos =
        (ASN1Set)
            attestationApplicationIdSequence.getObjectAt(
                ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX);
    ImmutableList<AttestationPackageInfo> packageInfos =
        stream(attestationPackageInfos.iterator())
            .map(ASN1Sequence.class::cast)
            .map(AttestationPackageInfo::create)
            .collect(toImmutableList());

    ASN1Set digests =
        (ASN1Set)
            attestationApplicationIdSequence.getObjectAt(
                ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX);
    ImmutableList<ByteString> signatureDigests =
        stream(digests.iterator())
            .map(ASN1OctetString.class::cast)
            .map(ASN1OctetString::getOctets)
            .map(ByteString::copyFrom)
            .collect(toImmutableList());
    return AttestationApplicationId.create(packageInfos, signatureDigests);
  }

  ASN1Sequence toAsn1Sequence() {
    ASN1Encodable[] applicationIdAsn1Array = new ASN1Encodable[2];
    applicationIdAsn1Array[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] =
        new DERSet(
            packageInfos().stream()
                .map(AttestationPackageInfo::toAsn1Sequence)
                .toArray(ASN1Sequence[]::new));
    applicationIdAsn1Array[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] =
        new DERSet(
            signatureDigests().stream()
                .map(ByteString::toByteArray)
                .map(DEROctetString::new)
                .toArray(DEROctetString[]::new));

    return new DERSequence(applicationIdAsn1Array);
  }

  /** Provides package's name and version number. */
  @AutoValue
  @Immutable
  public abstract static class AttestationPackageInfo {
    public abstract String packageName();

    public abstract long version();

    private static AttestationPackageInfo create(ASN1Sequence packageInfo) {
      String packageName =
          new String(
              ((ASN1OctetString)
                      packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX))
                  .getOctets(),
              UTF_8);
      long version =
          ((ASN1Integer) packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_VERSION_INDEX))
              .getValue()
              .longValue();
      return AttestationPackageInfo.create(packageName, version);
    }

    public static AttestationPackageInfo create(String packageName, long version) {
      return new AutoValue_AttestationApplicationId_AttestationPackageInfo(packageName, version);
    }

    ASN1Sequence toAsn1Sequence() {
      ASN1Encodable[] packageInfoAsn1Array = new ASN1Encodable[2];
      packageInfoAsn1Array[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] =
          new DEROctetString(packageName().getBytes(UTF_8));
      packageInfoAsn1Array[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] = new ASN1Integer(version());
      return new DERSequence(packageInfoAsn1Array);
    }
  }
}
