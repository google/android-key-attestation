load("@rules_kotlin//kotlin:jvm.bzl", "kt_jvm_library")

package(default_visibility = ["//visibility:public"])

java_plugin(
    name = "auto_plugin",
    processor_class = "com.google.auto.value.processor.AutoValueProcessor",
    deps = ["@maven//:com_google_auto_value_auto_value"],
)

java_library(
    name = "auto",
    exported_plugins = [":auto_plugin"],
    exports = [
        "@maven//:com_google_auto_value_auto_value",
        "@maven//:com_google_auto_value_auto_value_annotations",
    ],
)

kt_jvm_library(
    name = "attestation",
    srcs = [
        "ASN1Parsing.kt",
        "AttestationApplicationId.java",
        "AuthorizationList.java",
        "Constants.java",
        "ParsedAttestationRecord.java",
        "RootOfTrust.java",
    ],
    deps = [
        ":auto",
        "@maven//:com_google_errorprone_error_prone_annotations",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_protobuf_protobuf_javalite",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)
