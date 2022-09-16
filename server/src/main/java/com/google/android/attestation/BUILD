package(default_visibility = ["//visibility:public"])

java_library(
    name = "attestation",
    srcs = [
        "ASN1Parsing.java",
        "AttestationApplicationId.java",
        "AuthorizationList.java",
        "CertificateRevocationStatus.java",
        "Constants.java",
        "ParsedAttestationRecord.java",
        "RootOfTrust.java",
    ],
    deps = [
        "@maven//:com_google_code_gson_gson",
        "@maven//:org_bouncycastle_bcpkix_jdk15on",
        "@maven//:org_bouncycastle_bcprov_jdk15on",
    ],
)
