# Permission Test Tool Companion  
This sample app is a tool which aids OEMs in testing their devices for
evaluation of the Common Criteria certificate through
[NIAP](https://www.niap-ccevs.org/).

## Introduction
The Permission Test Tool under the `Tester/` directory performs tests to verify
the platform declared permissions properly guard their respective APIs,
resources, etc. However a number of these tests require additional setup on the
device under test; this companion app performs the necessary setup.

## Additional Details
This app should be installed and run on the device under test before the
Permission Test Tool is run.

This app should be signed with a different signing key from that used to sign
the Permission Test Tool; if the two apps have the same signing identity it can
cause some of the permission tests to fail.

## Functionalities
 
 - This application provides entry points to the services, we can test the permissions 
 which have 'BIND_*' prefix with these.
 - Install several media files for testing
 - Put a data into the DropBox
 - Prepare hidden flags to test device policy manager test cases.
   - You can toggle this flags by a checkbox on the bottom of the activity. 
 - Check the behaviour of the location manager.

## Pre-requisites
* Android SDK 28+

## Getting Started
This sample uses the Gradle build system. To build this project, use the
`gradlew build` command or use `Import Project` in Android Studio.

Also You can publish apk file into the Tester/package directory with `./gradlew publishAll` command 

## Support
If you've found an error in this sample, please file an issue on the github bug
tracker for this project.

Please see `Contributing.md` in the project root for more details.

