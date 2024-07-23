import org.jetbrains.kotlin.gradle.internal.Kapt3GradleSubplugin.Companion.isIncludeCompileClasspath

/*
 * This file was generated by the Gradle 'init' task.
 *
 * This generated file contains a sample Gradle plugin project to get you started.
 * For more details on writing Custom Plugins, please refer to https://docs.gradle.org/8.7/userguide/custom_plugins.html in the Gradle documentation.
 * This project uses @Incubating APIs which are subject to change.
 */

plugins {
    antlr
    // Apply the Java Gradle plugin development plugin to add support for developing Gradle plugins
    `java-gradle-plugin`

    //`kotlin-dsl`
    // Apply the Kotlin JVM plugin to add support for Kotlin.
    alias(libs.plugins.jvm)
    //id("com.github.johnrengelman.shadow") version "8.1.1"
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

repositories {
    // Use Maven Central for resolving dependencies.
    google()
    mavenCentral()
}

tasks.jar { enabled = true }

tasks.shadowJar {
    // required by the plugin-publish-plugin
    archiveClassifier = ""
}


dependencies {
    implementation("com.github.javaparser:javaparser-core:3.3.0")
    implementation("com.google.guava:guava:32.0.1-jre")
    implementation("org.jboss.forge.roaster:roaster-jdt:2.29.0.Final")
    antlr("org.antlr:antlr4:4.7.2")
    //classpath( "com.github.javaparser:javaparser-core:3.3.0")
}


testing {
    suites {
        // Configure the built-in test suite
        val test by getting(JvmTestSuite::class) {
            // Use Kotlin Test test framework
            useKotlinTest("1.9.22")
        }

        // Create a new test suite
        val functionalTest by registering(JvmTestSuite::class) {
            // Use Kotlin Test test framework
            useKotlinTest("1.9.22")

            dependencies {
                // functionalTest test suite depends on the production code in tests
                implementation(project())
            }

            targets {
                all {
                    // This test suite should run after the built-in test suite has run its tests
                    testTask.configure { shouldRunAfter(test) } 
                }
            }
        }
    }
}

gradlePlugin {
    // Define the plugin
    val greeting by plugins.creating {
        id = "niap.codeporter"
        implementationClass = "niap.codeporter.CodePorterPlugin"
    }
}

gradlePlugin.testSourceSets.add(sourceSets["functionalTest"])

tasks.named<Task>("check") {
    // Include functionalTest as part of the check lifecycle
    dependsOn(testing.suites.named("functionalTest"))
}

tasks.named<AntlrTask>("generateGrammarSource") {
    maxHeapSize = "64m"
    arguments = arguments + listOf("-visitor", "-long-messages")
    dependsOn("compileKotlin")
}