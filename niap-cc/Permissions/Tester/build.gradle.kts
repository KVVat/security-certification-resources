/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Top-level build file where you can add configuration options common to all sub-projects/modules.
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.4.2")
        classpath("com.google.guava:guava:24.1-jre")
        classpath("org.codehaus.groovy:groovy-json:3.0.9")
        classpath( "com.github.javaparser:javaparser-core:3.3.0")
        // NOTE: Do not place your application dependencies here; they belong
        // in the individual module build.gradle.kts files

    }
}


allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

//To run app:publishAll to export all variants into package direcotory.=>see app: build.gradle
