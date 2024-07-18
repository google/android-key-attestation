load("@rules_kotlin//kotlin:jvm.bzl", "kt_jvm_test")

kt_jvm_test(
    name = "AttestationApplicationIdTest",
    srcs = ["AttestationApplicationIdTest.kt"],
    deps = [
        "//src/main/java/com/google/android/attestation",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_protobuf_protobuf_javalite",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
    ],
)

kt_jvm_test(
    name = "AuthorizationListTest",
    srcs = ["AuthorizationListTest.kt"],
    deps = [
        "//src/main/java/com/google/android/attestation",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)

kt_jvm_test(
    name = "ParsedAttestationRecordTest",
    srcs = ["ParsedAttestationRecordTest.kt"],
    deps = [
        "//src/main/java/com/google/android/attestation",
        "@maven//:com_google_protobuf_protobuf_javalite",
        "@maven//:com_google_testparameterinjector_test_parameter_injector",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)

kt_jvm_test(
    name = "RootOfTrustTest",
    srcs = ["RootOfTrustTest.kt"],
    deps = [
        "//src/main/java/com/google/android/attestation",
        "@maven//:com_google_protobuf_protobuf_javalite",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
)
