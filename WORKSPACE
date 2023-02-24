workspace(
    name = "android-key-attestation",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

RULES_JVM_EXTERNAL_TAG = "4.2"

RULES_JVM_EXTERNAL_SHA = "cd1a77b7b02e8e008439ca76fd34f5b07aecb8c752961f9640dea15e9e5ba1ca"

http_archive(
    name = "rules_jvm_external",
    sha256 = RULES_JVM_EXTERNAL_SHA,
    strip_prefix = "rules_jvm_external-%s" % RULES_JVM_EXTERNAL_TAG,
    url = "https://github.com/bazelbuild/rules_jvm_external/archive/%s.zip" % RULES_JVM_EXTERNAL_TAG,
)

load("@rules_jvm_external//:repositories.bzl", "rules_jvm_external_deps")

rules_jvm_external_deps()

load("@rules_jvm_external//:setup.bzl", "rules_jvm_external_setup")

rules_jvm_external_setup()

load("@rules_jvm_external//:defs.bzl", "maven_install")

maven_install(
    artifacts = [
        # Bouncy Castle Cryptography APIs used for certificate verification
        "org.bouncycastle:bcpkix-jdk15on:1.61",
        "org.bouncycastle:bcprov-jdk15on:1.61",

        # Gson used for decoding certificate status list
        "com.google.code.gson:gson:2.8.5",

        "com.google.guava:guava:27.0.1-android",
        "com.google.errorprone:error_prone_annotations:2.3.1",


        # Test libraries
        "junit:junit:4.12",
        "com.google.truth:truth:1.0",
        "com.google.truth.extensions:truth-java8-extension:1.0",
    ],
    repositories = [
        "https://repo1.maven.org/maven2/",
    ],
)
