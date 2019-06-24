package com.android.example;

import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import static com.android.example.Constants.*;

public class ParsedAttestationRecord {

  private int attestationVersion;
  private SecurityLevel securityLevel;
  private Integer keyMasterVersion;
  private byte[] attestationChallenge;
  private byte[] uniqueId;
  private AuthorizationList softwareEnforced;
  private AuthorizationList teeEnforced;

  public ParsedAttestationRecord(X509Certificate extensionData) {
    // TODO: parse extensionData to get each key
    // TODO: decrease coupling by letting AuthorizationList do it's own parsing
  }

  private static ASN1Sequence extractAttestationSequence(X509Certificate attestationCert)
      throws Exception {
    byte[] attestationExtensionBytes = attestationCert.getExtensionValue(KEY_DESCRIPTION_OID);
    if (attestationExtensionBytes == null || attestationExtensionBytes.length == 0) {
      throw new Exception("Couldn't find the keystore attestation extension data.");
    }

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

  private static ASN1Primitive findAuthorizationListEntry(
      ASN1Encodable[] authorizationList, int tag) {
    for (ASN1Encodable entry : authorizationList) {
      ASN1TaggedObject taggedEntry = (ASN1TaggedObject) entry;
      if (taggedEntry.getTagNo() == tag) {
        return taggedEntry.getObject();
      }
    }
    return null;
  }

  private static String securityLevelToString(int securityLevel) throws Exception {
    switch (securityLevel) {
      case KM_SECURITY_LEVEL_SOFTWARE:
        return "Software";
      case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
        return "TEE";
      default:
        throw new Exception("Invalid security level.");
    }
  }

  private static int getIntegerFromAsn1(ASN1Encodable asn1Value) throws Exception {
    if (asn1Value instanceof ASN1Integer) {
      return bigIntegerToInt(((ASN1Integer) asn1Value).getValue());
    } else if (asn1Value instanceof ASN1Enumerated) {
      return bigIntegerToInt(((ASN1Enumerated) asn1Value).getValue());
    } else {
      throw new Exception(
          "Integer value expected; found " + asn1Value.getClass().getName() + " instead.");
    }
  }

  private static int bigIntegerToInt(BigInteger bigInt) throws Exception {
    if (bigInt.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0
        || bigInt.compareTo(BigInteger.ZERO) < 0) {
      throw new Exception("INTEGER out of bounds");
    }
    return bigInt.intValue();
  }

  public enum SecurityLevel {
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONG_BOX
  }
}
