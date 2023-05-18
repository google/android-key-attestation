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
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
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
public class AttestationApplicationId implements Comparable<AttestationApplicationId> {
  public final List<AttestationPackageInfo> packageInfos;
  public final List<byte[]> signatureDigests;

  private AttestationApplicationId(DEROctetString attestationApplicationId) throws IOException {
    ASN1Sequence attestationApplicationIdSequence =
        (ASN1Sequence) ASN1Sequence.fromByteArray(attestationApplicationId.getOctets());
    ASN1Set attestationPackageInfos =
        (ASN1Set)
            attestationApplicationIdSequence.getObjectAt(
                ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX);
    packageInfos = new ArrayList<>();
    for (ASN1Encodable packageInfo : attestationPackageInfos) {
      packageInfos.add(new AttestationPackageInfo((ASN1Sequence) packageInfo));
    }

    ASN1Set digests =
        (ASN1Set)
            attestationApplicationIdSequence.getObjectAt(
                ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX);
    signatureDigests = new ArrayList<>();
    for (ASN1Encodable digest : digests) {
      signatureDigests.add(((ASN1OctetString) digest).getOctets());
    }
  }

  public AttestationApplicationId(
      List<AttestationPackageInfo> packageInfos, List<byte[]> signatureDigests) {
    this.packageInfos = packageInfos;
    this.signatureDigests = signatureDigests;
  }

  static AttestationApplicationId createAttestationApplicationId(
      DEROctetString attestationApplicationId) {
    if (attestationApplicationId == null) {
      return null;
    }
    try {
      return new AttestationApplicationId(attestationApplicationId);
    } catch (IOException e) {
      return null;
    }
  }

  ASN1Sequence toAsn1Sequence() {
    ASN1Encodable[] applicationIdAsn1Array = new ASN1Encodable[2];
    ASN1EncodableVector tmpPackageInfos = new ASN1EncodableVector();
    packageInfos.forEach(packageInfo -> tmpPackageInfos.add(packageInfo.toAsn1Sequence()));
    applicationIdAsn1Array[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] =
        new DERSet(tmpPackageInfos);

    ASN1EncodableVector tmpSignatureDigests = new ASN1EncodableVector();
    signatureDigests.forEach(digest -> tmpSignatureDigests.add(new DEROctetString(digest)));
    applicationIdAsn1Array[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] =
        new DERSet(tmpSignatureDigests);

    return new DERSequence(applicationIdAsn1Array);
  }

  @Override
  public int compareTo(AttestationApplicationId other) {
    int res = Integer.compare(packageInfos.size(), other.packageInfos.size());
    if (res != 0) {
      return res;
    }
    for (int i = 0; i < packageInfos.size(); ++i) {
      res = packageInfos.get(i).compareTo(other.packageInfos.get(i));
      if (res != 0) {
        return res;
      }
    }
    res = Integer.compare(signatureDigests.size(), other.signatureDigests.size());
    if (res != 0) {
      return res;
    }
    ByteArrayComparator cmp = new ByteArrayComparator();
    for (int i = 0; i < signatureDigests.size(); ++i) {
      res = cmp.compare(signatureDigests.get(i), other.signatureDigests.get(i));
      if (res != 0) {
        return res;
      }
    }
    return res;
  }

  @Override
  public boolean equals(Object o) {
    return (o instanceof AttestationApplicationId)
        && (compareTo((AttestationApplicationId) o) == 0);
  }

  @Override
  public int hashCode() {
    return Objects.hash(packageInfos, Arrays.deepHashCode(signatureDigests.toArray()));
  }

  /** Provides package's name and version number. */
  public static class AttestationPackageInfo implements Comparable<AttestationPackageInfo> {
    public final String packageName;
    public final long version;

    private AttestationPackageInfo(ASN1Sequence packageInfo) {
      packageName =
          new String(
              ((ASN1OctetString)
                      packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX))
                  .getOctets(),
              UTF_8);
      version =
          ((ASN1Integer) packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_VERSION_INDEX))
              .getValue()
              .longValue();
    }

    public AttestationPackageInfo(String packageName, long version) {
      this.packageName = packageName;
      this.version = version;
    }

    ASN1Sequence toAsn1Sequence() {
      ASN1Encodable[] packageInfoAsn1Array = new ASN1Encodable[2];
      packageInfoAsn1Array[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] =
          new DEROctetString(packageName.getBytes(UTF_8));
      packageInfoAsn1Array[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] = new ASN1Integer(version);
      return new DERSequence(packageInfoAsn1Array);
    }

    @Override
    public int compareTo(AttestationPackageInfo other) {
      int res = packageName.compareTo(other.packageName);
      if (res != 0) {
        return res;
      }
      res = Long.compare(version, other.version);
      if (res != 0) {
        return res;
      }
      return res;
    }

    @Override
    public boolean equals(Object o) {
      return (o instanceof AttestationPackageInfo) && (compareTo((AttestationPackageInfo) o) == 0);
    }

    @Override
    public int hashCode() {
      return Objects.hash(packageName, version);
    }
  }

  private static class ByteArrayComparator implements java.util.Comparator<byte[]> {
    @Override
    public int compare(byte[] a, byte[] b) {
      int res = Integer.compare(a.length, b.length);
      if (res != 0) {
        return res;
      }
      for (int i = 0; i < a.length; ++i) {
        res = Byte.compare(a[i], b[i]);
        if (res != 0) {
          return res;
        }
      }
      return res;
    }
  }
}
