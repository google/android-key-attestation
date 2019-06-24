package com.android.example;

class Constants {
  static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";

  static final int ATTESTATION_VERSION_INDEX = 0;
  static final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
  static final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
  static final int ATTESTATION_CHALLENGE_INDEX = 4;
  static final int SW_ENFORCED_INDEX = 6;
  static final int TEE_ENFORCED_INDEX = 7;

  // Some authorization list tags. The complete list is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  static final int KM_TAG_PURPOSE = 1;
  static final int KM_TAG_ALGORITHM = 2;
  static final int KM_TAG_KEY_SIZE = 3;
  static final int KM_TAG_USER_AUTH_TYPE = 504;
  static final int KM_TAG_AUTH_TIMEOUT = 505;
  static final int KM_TAG_ORIGIN = 702;
  static final int KM_TAG_ROLLBACK_RESISTANT = 703;

  // The complete list of purpose values is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  static final int KM_PURPOSE_SIGN = 2;

  // The complete list of algorithm values is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  static final int KM_ALGORITHM_RSA = 1;
  static final int KM_ALGORITHM_EC = 3;

  // Some authentication type values. The complete list is in this AOSP file:
  // hardware/libhardware/include/hardware/hw_auth_token.h
  static final int HW_AUTH_PASSWORD = 1 << 0;
  static final int HW_AUTH_FINGERPRINT = 1 << 1;

  // The complete list of origin values is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  static final int KM_ORIGIN_GENERATED = 0;

  // Some security values. The complete list is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
  static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;

  // The Google root certificate that must have been used to sign the root
  // certificate in a real attestation certificate chain from a compliant
  // device.
  // (Note, the sample chain used here is not signed with this certificate.)
  static final String GOOGLE_ROOT_CERTIFICATE =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV"
          + "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy"
          + "ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B"
          + "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS"
          + "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7"
          + "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj"
          + "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq"
          + "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ"
          + "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O"
          + "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg"
          + "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi"
          + "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M"
          + "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E"
          + "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um"
          + "AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD"
          + "VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO"
          + "BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk"
          + "Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD"
          + "ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB"
          + "Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m"
          + "qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY"
          + "DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm"
          + "QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u"
          + "JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD"
          + "CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy"
          + "ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD"
          + "qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic"
          + "MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1"
          + "wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk\n"
          + "-----END CERTIFICATE-----";

  // Attestation certificate used for sample purposes.
  static final String ATTESTATION_CERTIFICATE =
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
  static final String INTERMEDIATE_CERTIFICATE =
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
  static final String ROOT_CERTIFICATE =
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
  static final String[] SAMPLE_ATTESTATION_CERT_CHAIN =
      new String[]{ATTESTATION_CERTIFICATE, INTERMEDIATE_CERTIFICATE, ROOT_CERTIFICATE};
}
