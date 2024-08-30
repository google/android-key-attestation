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

import static com.google.android.attestation.Constants.ATTESTATION_CHALLENGE_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_SECURITY_LEVEL_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_VERSION_INDEX;
import static com.google.android.attestation.Constants.KEYMASTER_SECURITY_LEVEL_INDEX;
import static com.google.android.attestation.Constants.KEYMASTER_VERSION_INDEX;
import static com.google.android.attestation.Constants.KEY_DESCRIPTION_OID;
import static com.google.android.attestation.Constants.KM_SECURITY_LEVEL_SOFTWARE;
import static com.google.android.attestation.Constants.KM_SECURITY_LEVEL_STRONG_BOX;
import static com.google.android.attestation.Constants.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
import static com.google.android.attestation.Constants.SW_ENFORCED_INDEX;
import static com.google.android.attestation.Constants.TEE_ENFORCED_INDEX;
import static com.google.android.attestation.Constants.UNIQUE_ID_INDEX;

import com.google.auto.value.AutoValue;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/** Java representation of Key Attestation extension data. */
@AutoValue
@Immutable
public abstract class ParsedAttestationRecord {

  public abstract int attestationVersion();

  public abstract SecurityLevel attestationSecurityLevel();

  public abstract int keymasterVersion();

  public abstract SecurityLevel keymasterSecurityLevel();

  public abstract ByteString attestationChallenge();

  public abstract ByteString uniqueId();

  public abstract AuthorizationList softwareEnforced();

  public abstract AuthorizationList teeEnforced();

  @AutoValue.CopyAnnotations
  @SuppressWarnings("Immutable")
  public abstract PublicKey attestedKey();

  public abstract Builder toBuilder();

  public static Builder builder() {
    return new AutoValue_ParsedAttestationRecord.Builder()
        .setAttestationChallenge(ByteString.EMPTY)
        .setUniqueId(ByteString.EMPTY)
        .setSoftwareEnforced(AuthorizationList.builder().build())
        .setTeeEnforced(AuthorizationList.builder().build());
  }

  /** Builder for {@link ParsedAttestationRecord}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setAttestationVersion(int value);

    public abstract Builder setAttestationSecurityLevel(SecurityLevel value);

    public abstract Builder setKeymasterVersion(int value);

    public abstract Builder setKeymasterSecurityLevel(SecurityLevel value);

    public abstract Builder setAttestationChallenge(ByteString value);

    @CanIgnoreReturnValue
    public final Builder setAttestationChallenge(byte[] value) {
      return setAttestationChallenge(ByteString.copyFrom(value));
    }

    public abstract Builder setUniqueId(ByteString value);

    @CanIgnoreReturnValue
    public final Builder setUniqueId(byte[] value) {
      return setUniqueId(ByteString.copyFrom(value));
    }

    public abstract Builder setSoftwareEnforced(AuthorizationList value);

    public abstract Builder setTeeEnforced(AuthorizationList value);

    public abstract Builder setAttestedKey(PublicKey value);

    public abstract ParsedAttestationRecord build();
  }

  public static ParsedAttestationRecord createParsedAttestationRecord(List<X509Certificate> certs)
      throws IOException {

    // Parse the attestation record that is closest to the root. This prevents an adversary from
    // attesting an attestation record of their choice with an otherwise trusted chain using the
    // following attack:
    // 1) having the TEE attest a key under the adversary's control,
    // 2) using that key to sign a new leaf certificate with an attestation extension that has their
    //    chosen attestation record, then
    // 3) appending that certificate to the original certificate chain.
    for (int i = certs.size() - 1; i >= 0; i--) {
      byte[] attestationExtensionBytes = certs.get(i).getExtensionValue(KEY_DESCRIPTION_OID);
      if (attestationExtensionBytes != null && attestationExtensionBytes.length != 0) {
        return ParsedAttestationRecord.create(
            extractAttestationSequence(attestationExtensionBytes), certs.get(i).getPublicKey());
      }
    }

    throw new IllegalArgumentException("Couldn't find the keystore attestation extension data.");
  }

  public static ParsedAttestationRecord create(ASN1Sequence extensionData, PublicKey attestedKey) {
    Builder builder = builder();
    int attestationVersion =
        ASN1Parsing.getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_VERSION_INDEX));
    builder.setAttestationVersion(attestationVersion);
    builder.setAttestationSecurityLevel(
        securityLevelToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                extensionData.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX))));
    builder.setKeymasterVersion(
        ASN1Parsing.getIntegerFromAsn1(extensionData.getObjectAt(KEYMASTER_VERSION_INDEX)));
    builder.setKeymasterSecurityLevel(
        securityLevelToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                extensionData.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX))));
    builder.setAttestationChallenge(
        ASN1OctetString.getInstance(extensionData.getObjectAt(ATTESTATION_CHALLENGE_INDEX))
            .getOctets());
    builder.setUniqueId(
        ASN1OctetString.getInstance(extensionData.getObjectAt(UNIQUE_ID_INDEX)).getOctets());
    builder.setSoftwareEnforced(
        AuthorizationList.createAuthorizationList(
            ASN1Sequence.getInstance(extensionData.getObjectAt(SW_ENFORCED_INDEX)).toArray(),
            attestationVersion));
    builder.setTeeEnforced(
        AuthorizationList.createAuthorizationList(
            ASN1Sequence.getInstance(extensionData.getObjectAt(TEE_ENFORCED_INDEX)).toArray(),
            attestationVersion));
    builder.setAttestedKey(attestedKey);
    return builder.build();
  }

  private static SecurityLevel securityLevelToEnum(int securityLevel) {
    switch (securityLevel) {
      case KM_SECURITY_LEVEL_SOFTWARE:
        return SecurityLevel.SOFTWARE;
      case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
        return SecurityLevel.TRUSTED_ENVIRONMENT;
      case KM_SECURITY_LEVEL_STRONG_BOX:
        return SecurityLevel.STRONG_BOX;
      default:
        throw new IllegalArgumentException("Invalid security level.");
    }
  }

  private static int securityLevelToInt(SecurityLevel securityLevel) {
    switch (securityLevel) {
      case SOFTWARE:
        return KM_SECURITY_LEVEL_SOFTWARE;
      case TRUSTED_ENVIRONMENT:
        return KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
      case STRONG_BOX:
        return KM_SECURITY_LEVEL_STRONG_BOX;
    }
    throw new IllegalArgumentException("Invalid security level.");
  }

  private static ASN1Sequence extractAttestationSequence(byte[] attestationExtensionBytes)
      throws IOException {
    ASN1Sequence decodedSequence;
    try (ASN1InputStream asn1InputStream = new ASN1InputStream(attestationExtensionBytes)) {
      // The extension contains one object, a sequence, in the
      // Distinguished Encoding Rules (DER)-encoded form. Get the DER
      // bytes.
      byte[] derSequenceBytes = ((ASN1OctetString) asn1InputStream.readObject()).getOctets();
      // Decode the bytes as an ASN1 sequence object.
      try (ASN1InputStream seqInputStream = new ASN1InputStream(derSequenceBytes)) {
        decodedSequence = (ASN1Sequence) seqInputStream.readObject();
      }
    }
    return decodedSequence;
  }

  public ASN1Sequence toAsn1Sequence() {
    ASN1Encodable[] vector = new ASN1Encodable[8];
    vector[ATTESTATION_VERSION_INDEX] = new ASN1Integer(this.attestationVersion());
    vector[ATTESTATION_SECURITY_LEVEL_INDEX] =
        new ASN1Enumerated(securityLevelToInt(this.attestationSecurityLevel()));
    vector[KEYMASTER_VERSION_INDEX] = new ASN1Integer(this.keymasterVersion());
    vector[KEYMASTER_SECURITY_LEVEL_INDEX] =
        new ASN1Enumerated(securityLevelToInt(this.keymasterSecurityLevel()));
    vector[ATTESTATION_CHALLENGE_INDEX] =
        new DEROctetString(this.attestationChallenge().toByteArray());
    vector[UNIQUE_ID_INDEX] = new DEROctetString(this.uniqueId().toByteArray());
    if (this.softwareEnforced() != null) {
      vector[SW_ENFORCED_INDEX] = this.softwareEnforced().toAsn1Sequence();
    }
    if (this.teeEnforced() != null) {
      vector[TEE_ENFORCED_INDEX] = this.teeEnforced().toAsn1Sequence();
    }
    return new DERSequence(vector);
  }

  /**
   * This indicates the extent to which a software feature, such as a key pair, is protected based
   * on its location within the device.
   */
  public enum SecurityLevel {
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONG_BOX
  }
}
