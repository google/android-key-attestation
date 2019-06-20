/* Copyright 2016, The Android Open Source Project, Inc.
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

package com.android.example;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;

/**
 * This is an illustration of how you can use the Bouncy Castle ASN.1 parser to extract information
 * from an Android attestation data structure. On a secure server that you trust, create similar
 * logic to verify that a key pair has been generated in an Android device. The app on the device
 * must retrieve the key's certificate chain using KeyStore.getCertificateChain(), then send the
 * contents to the trusted server.
 *
 * <p>In this example, the certificate chain includes hard-coded excerpts of each certificate.
 *
 * <p>This example demonstrates the following tasks:
 *
 * <p>1. Loading the certificates from PEM-encoded strings.
 *
 * <p>2. Verifying the certificate chain, up to the root. Note that this example does NOT require
 * the root certificate to appear within Google's list of root certificates. However, if you're
 * verifying the properties of hardware-backed keys on a device that ships with hardware-level key
 * attestation, Android 7.0 (API level 24) or higher, and Google Play services, your production code
 * should enforce this requirement.
 *
 * <p>3. Extracting the attestation extension data from the attestation certificate.
 *
 * <p>4. Verifying (and printing) several important data elements from the attestation extension.
 *
 * <p>Although this sample code doesn't check the revocation status of intermediate and root
 * certificates, you should do so in production-level code. Note that attestation certificates don't
 * have certificate revocation lists.
 */
public class KeyAttestationExample {

  // The Google root certificate that must have been used to sign the root
  // certificate in a real attestation certificate chain from a compliant
  // device.
  // (Note, the sample chain used here is not signed with this certificate.)
  public static final String GOOGLE_ROOT_CERTIFICATE =
      "-----BEGIN CERTIFICATE-----\n"
          + "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\n"
          + "-----END CERTIFICATE-----";
  // Attestation certificate used for sample purposes.
  public static final String ATTESTATION_CERTIFICATE =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIByTCCAXCgAwIBAgIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFBbmRyb2lkIE"
          + "tleW1hc3Rl cjAgFw03MDAxMDEwMDAwMDBaGA8yMTA2MDIwNzA2MjgxNVowGjEYMBY"
          + "GA1UEAwwPQSBLZXltYXN0 ZXIgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"
          + "FpsFUWID9p2QPAvtfal4MRf9vJg0tNc3 vKJwoDhhSCMm7If0FljgvmroBYQyCIbnn"
          + "Bxh2OU9SKxI/manPwIIUqOBojCBnzALBgNVHQ8EBAMC B4AwbwYKKwYBBAHWeQIBEQ"
          + "RhMF8CAQEKAQACAQEKAQEEBWhlbGxvBAAwDL+FPQgCBgFWDy29GDA6 oQUxAwIBAqI"
          + "DAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBA7+DeQQCAgEsv4U+AwIBAL+FPwIF "
          + "ADAfBgNVHSMEGDAWgBQ//KzWGrE6noEguNUlHMVlux6RqTAKBggqhkjOPQQDAgNHAD"
          + "BEAiBKzJSk 9VNauKu4dr+ZJ5jMTNlAxSI99XkKEkXSolsGSAIgCnd5T99gv3B/IqM"
          + "CHn0yZ7Wuu/jisU0epRRo xh8otA8=\n"
          + "-----END CERTIFICATE-----";
  // Intermediate certificate in the attestation certificate chain, used for
  // sample purposes.
  public static final String INTERMEDIATE_CERTIFICATE =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQ"
          + "YDVQQIDApD YWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQ"
          + "KDAxHb29nbGUsIEluYy4x EDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJv"
          + "aWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0 ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwM"
          + "DQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQG EwJVUzETMBEGA1UECAwKQ2"
          + "FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQL DAdBbmRyb2l"
          + "kMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9u "
          + "IEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOueefhCY1msyy"
          + "qRTImGzHCt kGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8U7ego6ZxWD7"
          + "bPhGuEBSjZjBkMB0GA1Ud DgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfBgNVHSME"
          + "GDAWgBTIrel3TEXDo88NFhDkeUM6IVow zzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA"
          + "1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBL ipt77oK8wDOHri/AiZi03c"
          + "ONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsi u+f+uXc/WT/"
          + "7\n"
          + "-----END CERTIFICATE-----";
  // Root certificate in the attestation certificate chain, used for sample
  // purposes.
  public static final String ROOT_CERTIFICATE =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEw"
          + "JVUzETMBEG A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzE"
          + "VMBMGA1UECgwMR29vZ2xl LCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQD"
          + "DCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3 YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNM"
          + "TYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDEL MAkGA1UEBhMCVVMxEzARBg"
          + "NVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcx FTATBgNVBAo"
          + "MDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9p "
          + "ZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYHKoZIzj0CAQ"
          + "YIKoZIzj0D AQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/"
          + "6FsvHrcV30lacqrewLVQB XT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdM"
          + "RcOjzw0WEOR5QzohWjDPMB8GA1UdIwQY MBaAFMit6XdMRcOjzw0WEOR5QzohWjDPM"
          + "A8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKE MAoGCCqGSM49BAMCA0cAME"
          + "QCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR 2TB8fVvaNTQ"
          + "dqEcbY6WFZTytTySn502vQX3xvw==\n"
          + "-----END CERTIFICATE-----";
  // Certificate chain that contains three certificates that were generated
  // in software for this sample.
  public static final String[] SAMPLE_ATTESTATION_CERT_CHAIN =
      new String[] {ATTESTATION_CERTIFICATE, INTERMEDIATE_CERTIFICATE, ROOT_CERTIFICATE};
  private static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
  private static final int ATTESTATION_VERSION_INDEX = 0;
  private static final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
  private static final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
  private static final int ATTESTATION_CHALLENGE_INDEX = 4;
  private static final int SW_ENFORCED_INDEX = 6;
  private static final int TEE_ENFORCED_INDEX = 7;
  // Some authorization list tags. The complete list is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  private static final int KM_TAG_PURPOSE = 1;
  private static final int KM_TAG_ALGORITHM = 2;
  private static final int KM_TAG_KEY_SIZE = 3;
  private static final int KM_TAG_USER_AUTH_TYPE = 504;
  private static final int KM_TAG_AUTH_TIMEOUT = 505;
  private static final int KM_TAG_ORIGIN = 702;
  private static final int KM_TAG_ROLLBACK_RESISTANT = 703;
  // The complete list of purpose values is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  private static final int KM_PURPOSE_SIGN = 2;
  // The complete list of algorithm values is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  private static final int KM_ALGORITHM_EC = 3;
  // Some authentication type values. The complete list is in this AOSP file:
  // hardware/libhardware/include/hardware/hw_auth_token.h
  private static final int HW_AUTH_PASSWORD = 1 << 0;
  private static final int HW_AUTH_FINGERPRINT = 1 << 1;
  // The complete list of origin values is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  private static final int KM_ORIGIN_GENERATED = 0;
  // Some security values. The complete list is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  private static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
  private static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
  private static final int EXPECTED_ATTESTATION_VERSION = 1;

  public static void main(String[] args) throws Exception {
    X509Certificate[] certs = loadCertificates();
    verifyCertificateChain(certs);

    // Get the attestation extension data as an ASN.1 SEQUENCE.
    ASN1Sequence extensionData = extractAttestationSequence(certs[0]);

    // In the Bouncy Castle library, ASN.1 objects have reasonable
    // toString() methods, so if you want to display a quick view of the
    // key's characteristics, it's as easy as printing to a log.
    System.out.println("Attestion contents: " + extensionData);

    // The attestation version is important. If it's not the expected value,
    // then the extension data may be structured in a format that the parser
    // cannot recognize or accept.
    int attestationVersion =
        getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_VERSION_INDEX));
    if (attestationVersion != EXPECTED_ATTESTATION_VERSION) {
      throw new Exception("Unexpected attestation version. " + "Unable to parse extension data.");
    }

    // Use the attestation and keymaster security levels to determine
    // whether the device has a Trusted Execution Environment (TEE) and
    // whether the attestation certificate was generated in that TEE. In
    // this example, the test attestation certificate was generated on a
    // device with a TEE, but the certificate was generated in software.
    int attestationSecurityLevel =
        getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX));
    int keymasterSecurityLevel =
        getIntegerFromAsn1(extensionData.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX));
    System.out.println(
        "Attestation security level: " + securityLevelToString(attestationSecurityLevel));
    System.out.println(
        "Keymaster security level: " + securityLevelToString(keymasterSecurityLevel));
    if (attestationSecurityLevel != KM_SECURITY_LEVEL_SOFTWARE) {
      throw new Exception("Unexpected attestation security level value.");
    }
    if (keymasterSecurityLevel != KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT) {
      throw new Exception("Unexpected keymaster security level value.");
    }

    // Verify that the attestation challenge is correct. In a real system,
    // this would be a large (say, 16-byte) random byte string that was
    // generated by the server and sent to the device. The purpose of the
    // challenge is to prove that the key was generated in response to the
    // server's request, rather than already existing. In this this sample
    // certificate, the string "hello" is used.
    byte[] attestationChallenge =
        ((ASN1OctetString) extensionData.getObjectAt(ATTESTATION_CHALLENGE_INDEX)).getOctets();
    if (!Arrays.equals("hello".getBytes(), attestationChallenge)) {
      throw new Exception("Incorrect challenge string; key is not fresh");
    }

    // Now, you can check the detailed description of the key. It's divided
    // into two "authorization lists", one which is enforced by the TEE and
    // one which is enforced by Android keystore software. The list entries
    // describe what the key is, how you can and cannot use it, and the
    // location in which the key resides. This information determines
    // whether you can trust the key, even on a possibly-rooted device.
    // Each entry is an ASN1TaggedObject, so there's a tag
    // (such as KM_TAG_KEY_SIZE) that indicates the meaning of the value
    // (such as size of the key in bits).
    ASN1Encodable[] softwareEnforced =
        ((ASN1Sequence) extensionData.getObjectAt(SW_ENFORCED_INDEX)).toArray();
    ASN1Encodable[] teeEnforced =
        ((ASN1Sequence) extensionData.getObjectAt(TEE_ENFORCED_INDEX)).toArray();

    // Since this key is TEE-based, we expect to find the key size in the
    // TEE list.
    int keySize = getIntegerFromAsn1(findAuthorizationListEntry(teeEnforced, KM_TAG_KEY_SIZE));
    System.out.println("Key size: " + keySize);
    if (keySize != 256) {
      throw new Exception("The key does not have the expected size.");
    }

    // Similarly, the cryptographic algorithm is specified in the TEE list.
    int algorithm = getIntegerFromAsn1(findAuthorizationListEntry(teeEnforced, KM_TAG_ALGORITHM));
    System.out.println("Key cryptographic algorithm: " + algorithm);
    if (algorithm != KM_ALGORITHM_EC) {
      throw new Exception("This key is not an elliptic curve (EC) key, " + "which was expected.");
    }

    // This key should have been generated in the keystore, not imported
    // into it. (Even though there are valid cases for generating keys
    // outside of the keystore and importing them, it's better to generate
    // keys whenever possible.) Note that it's also possible to find the
    // origin entry in the software list, indicating whether it was
    // generated in a keystore or imported into it.
    int origin = getIntegerFromAsn1(findAuthorizationListEntry(teeEnforced, KM_TAG_ORIGIN));
    System.out.println("Key origin: " + origin);
    if (origin != KM_ORIGIN_GENERATED) {
      throw new Exception("This key does not have the expected origin.");
    }

    // Some entries, like "purpose", contain a set of values. Because this
    // key is based in the device's TEE, the key's purpose is included in
    // the TEE list. In this example, the key is only usable for signing. In
    // your app, keys may have other purposes, depending on how you use
    // them.
    ASN1Set purposes = (ASN1Set) findAuthorizationListEntry(teeEnforced, KM_TAG_PURPOSE);
    System.out.println("Key purpose(s): " + purposes);
    if (purposes == null
        || purposes.toArray().length != 1
        || getIntegerFromAsn1(purposes.toArray()[0]) != KM_PURPOSE_SIGN) {
      throw new Exception("This key does not have the expected purpose.");
    }

    // We expect this key to be authorized for use only if the user has
    // authenticated within the last 300 seconds (5 minutes).
    int authTimeout =
        getIntegerFromAsn1(findAuthorizationListEntry(teeEnforced, KM_TAG_AUTH_TIMEOUT));
    System.out.println("Key authorization timeout: " + authTimeout);
    if (authTimeout != 300) {
      throw new Exception("This key does not have " + "the expected authorization timeout.");
    }

    // The user can authenticate with either a password or a fingerprint
    // to authorize this key for use.
    int authTypes =
        getIntegerFromAsn1(findAuthorizationListEntry(teeEnforced, KM_TAG_USER_AUTH_TYPE));
    System.out.println("Key user authentication options: " + authTypes);
    if (authTypes != (HW_AUTH_FINGERPRINT | HW_AUTH_PASSWORD)) {
      throw new Exception("This key does not support " + "the expected authentication options.");
    }

    // A rollback-resistant key is one that is guaranteed to be gone
    // permanently when deleted. Boolean-valued entries like this one have
    // no meaningful value; if they are present, they are "true". So, if
    // findAuthorizationListEntry returns a non-null value, the key has this
    // property.
    boolean rollbackResistant =
        (null != findAuthorizationListEntry(teeEnforced, KM_TAG_ROLLBACK_RESISTANT));
    System.out.println("Key is rollback-resistant: " + rollbackResistant);
    if (!rollbackResistant) {
      // Normally, lack of rollback resistance is not an error condition,
      // but some security designs depend on it.
      throw new Exception("Key is not rollback resistant.");
    }
  }

  private static ASN1Sequence extractAttestationSequence(X509Certificate attestationCert)
      throws Exception {
    byte[] attestationExtensionBytes = attestationCert.getExtensionValue(KEY_DESCRIPTION_OID);
    if (attestationExtensionBytes == null || attestationExtensionBytes.length == 0) {
      throw new Exception("Couldn't find the keystore attestation " + "extension data.");
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

  private static void verifyCertificateChain(X509Certificate[] certs)
      throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
          NoSuchProviderException, SignatureException {
    for (int i = 1; i < certs.length; ++i) {
      // Verify that the certificate has not expired.
      certs[i].checkValidity();
      if (i > 0) {
        // Verify previous certificate with the public key from this
        // certificate. If verification fails, the verify() method
        // throws an exception.
        PublicKey pubKey = certs[i].getPublicKey();
        certs[i - 1].verify(pubKey);
        if (i == certs.length - 1) {
          // The last certificate (the root) is self-signed.
          certs[i].verify(pubKey);
        }
      }
    }

    // If the attestation is trustworthy and the device ships with hardware-
    // level key attestation, Android 7.0 (API level 24) or higher, and
    // Google Play services, the root certificate should be signed with the
    // Google attestation root key.
    X509Certificate secureRoot =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes()));
    if (Arrays.equals(
        secureRoot.getTBSCertificate(), certs[certs.length - 1].getTBSCertificate())) {
      System.out.println(
          "The root certificate is correct, so this attestation is trustworthy, as long as none of"
              + " the certificates in the chain have been revoked. A production-level system"
              + " should check the certificate revocation lists using the distribution points that"
              + " are listed in the intermediate and root certificates.");
    } else {
      System.out.println(
          "The root certificate is NOT correct. The attestation was probably generated by"
              + " software, not in secure hardware. This means that, although the attestation"
              + " contents are probably valid and correct, there is no proof that they are in fact"
              + " correct. If you're using a production-level system, you should now treat the"
              + " properties of this attestation certificate as advisory only, and you shouldn't"
              + " rely on this attestation certificate to provide security guarantees.");
    }
  }

  private static X509Certificate[] loadCertificates() throws CertificateException {
    // Load the attestation certificate chain.
    // The certificates below are retrieved from a software-generated sample.
    X509Certificate[] certs = new X509Certificate[SAMPLE_ATTESTATION_CERT_CHAIN.length];
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    for (int i = 0; i < SAMPLE_ATTESTATION_CERT_CHAIN.length; ++i) {
      certs[i] =
          (X509Certificate)
              factory.generateCertificate(
                  new ByteArrayInputStream(SAMPLE_ATTESTATION_CERT_CHAIN[i].getBytes()));
    }
    return certs;
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

  public static int getIntegerFromAsn1(ASN1Encodable asn1Value) throws Exception {
    if (asn1Value instanceof ASN1Integer) {
      return KeyAttestationExample.bigIntegerToInt(((ASN1Integer) asn1Value).getValue());
    } else if (asn1Value instanceof ASN1Enumerated) {
      return KeyAttestationExample.bigIntegerToInt(((ASN1Enumerated) asn1Value).getValue());
    } else {
      throw new Exception(
          "Integer value expected; found " + asn1Value.getClass().getName() + " instead.");
    }
  }

  static int bigIntegerToInt(BigInteger bigInt) throws Exception {
    if (bigInt.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0
        || bigInt.compareTo(BigInteger.ZERO) < 0) {
      throw new Exception("INTEGER out of bounds");
    }
    return bigInt.intValue();
  }
}
