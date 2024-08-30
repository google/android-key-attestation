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

import static com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_FAILED;
import static com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_SELF_SIGNED;
import static com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_UNVERIFIED;
import static com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_VERIFIED;
import static com.google.android.attestation.Constants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX;
import static com.google.android.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX;
import static com.google.android.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX;
import static com.google.android.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX;

import com.google.auto.value.AutoValue;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

/** This collection of values defines key information about the device's status. */
@AutoValue
@Immutable
public abstract class RootOfTrust {

  public abstract ByteString verifiedBootKey();

  public abstract boolean deviceLocked();

  public abstract VerifiedBootState verifiedBootState();

  public abstract Optional<ByteString> verifiedBootHash();

  public abstract Builder toBuilder();

  public static Builder builder() {
    return new AutoValue_RootOfTrust.Builder()
        .setVerifiedBootKey(ByteString.EMPTY)
        .setVerifiedBootHash(ByteString.EMPTY);
  }

  /** Builder for {@link RootOfTrust}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setVerifiedBootKey(ByteString value);

    @CanIgnoreReturnValue
    public final Builder setVerifiedBootKey(byte[] value) {
      return setVerifiedBootKey(ByteString.copyFrom(value));
    }

    public abstract Builder setDeviceLocked(boolean value);

    public abstract Builder setVerifiedBootState(VerifiedBootState value);

    public abstract Builder setVerifiedBootHash(ByteString value);

    @CanIgnoreReturnValue
    public final Builder setVerifiedBootHash(byte[] value) {
      setVerifiedBootHash(ByteString.copyFrom(value));
      return this;
    }

    public abstract RootOfTrust build();
  }

  static RootOfTrust createRootOfTrust(ASN1Sequence rootOfTrust, int attestationVersion) {
    Builder builder = RootOfTrust.builder();
    builder.setVerifiedBootKey(
        ASN1OctetString.getInstance(rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX))
            .getOctets());
    builder.setDeviceLocked(
        ASN1Parsing.getBooleanFromAsn1(rootOfTrust.getObjectAt(ROOT_OF_TRUST_DEVICE_LOCKED_INDEX)));
    builder.setVerifiedBootState(
        verifiedBootStateToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX))));
    if (attestationVersion >= 3) {
      builder.setVerifiedBootHash(
          ASN1OctetString.getInstance(
                  rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX))
              .getOctets());
    }
    return builder.build();
  }

  private static VerifiedBootState verifiedBootStateToEnum(int securityLevel) {
    switch (securityLevel) {
      case KM_VERIFIED_BOOT_STATE_VERIFIED:
        return VerifiedBootState.VERIFIED;
      case KM_VERIFIED_BOOT_STATE_SELF_SIGNED:
        return VerifiedBootState.SELF_SIGNED;
      case KM_VERIFIED_BOOT_STATE_UNVERIFIED:
        return VerifiedBootState.UNVERIFIED;
      case KM_VERIFIED_BOOT_STATE_FAILED:
        return VerifiedBootState.FAILED;
      default:
        throw new IllegalArgumentException("Invalid verified boot state.");
    }
  }

  private static int verifiedBootStateToInt(VerifiedBootState verifiedBootState) {
    switch (verifiedBootState) {
      case VERIFIED:
        return KM_VERIFIED_BOOT_STATE_VERIFIED;
      case SELF_SIGNED:
        return KM_VERIFIED_BOOT_STATE_SELF_SIGNED;
      case UNVERIFIED:
        return KM_VERIFIED_BOOT_STATE_UNVERIFIED;
      case FAILED:
        return KM_VERIFIED_BOOT_STATE_FAILED;
    }
    throw new IllegalArgumentException("Invalid verified boot state.");
  }

  /**
   * This provides the device's current boot state, which represents the level of protection
   * provided to the user and to apps after the device finishes booting.
   */
  public enum VerifiedBootState {
    VERIFIED,
    SELF_SIGNED,
    UNVERIFIED,
    FAILED
  }

  public ASN1Sequence toAsn1Sequence() {
    ASN1Encodable[] rootOfTrustElements;
    ByteString verifiedBootHash = this.verifiedBootHash().orElse(null);
    if (verifiedBootHash != null) {
      rootOfTrustElements = new ASN1Encodable[4];
      rootOfTrustElements[ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX] =
          new DEROctetString(verifiedBootHash.toByteArray());
    } else {
      rootOfTrustElements = new ASN1Encodable[3];
    }
    rootOfTrustElements[ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX] =
        new DEROctetString(this.verifiedBootKey().toByteArray());
    rootOfTrustElements[ROOT_OF_TRUST_DEVICE_LOCKED_INDEX] =
        ASN1Boolean.getInstance(this.deviceLocked());
    rootOfTrustElements[ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX] =
        new ASN1Enumerated(verifiedBootStateToInt(this.verifiedBootState()));
    return new DERSequence(rootOfTrustElements);
  }
}
