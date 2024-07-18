load("@rules_kotlin//kotlin:jvm.bzl", "kt_jvm_library")

package(default_visibility = ["//visibility:public"])

kt_jvm_library(
    name = "attestation",
    srcs = [
        "ASN1Parsing.kt",
        "AttestationApplicationId.kt",
        "AuthorizationList.kt",
        "Constants.kt",
        "ParsedAttestationRecord.kt",
        "RootOfTrust.kt",
    ],
    deps = [
        "@maven//:com_google_errorprone_error_prone_annotations",
        "@maven//:com_google_protobuf_protobuf_javalite",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)
