plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.7.0"
}

include(":app")
includeBuild("gradle/code-porter-plugin")