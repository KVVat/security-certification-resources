/*
 * Copyright 2020 The Android Open Source Project
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

package com.android.certifications.niap.permissions;

import android.app.Activity;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;

import androidx.core.util.Consumer;

import com.android.certifications.niap.permissions.activities.LogListAdaptable;
import com.android.certifications.niap.permissions.config.TestConfiguration;
import com.android.certifications.niap.permissions.log.Logger;
import com.android.certifications.niap.permissions.log.LoggerFactory;
import com.android.certifications.niap.permissions.log.StatusLogger;
import com.android.certifications.niap.permissions.utils.PermissionUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Permission tester to verify signature permissions declared by preloaded apps can only be granted
 * to an app signed with the same signing key as the app declaring the permission or an app signed
 * with the platform's signing key.
 * <p>Note, by default this tester dynamically queries for the signature permissions declared by all
 * non-platform apps on the device. The {@code AndroidManifest.xml} must be updated with {@code
 * uses-permission} tags for each of these permission declared on the device. Alternatively the
 * configuration for this tester can include a static list of permissions to test in {@code
 * TestConfiguration#getPermissions}. If a static permission list is used this tester will use the
 * dynamically queried permissions to ensure that the permission is defined on the system to avoid
 * false positives when the permission should have been granted.
 */
public class NonPlatformPermissionTester extends BasePermissionTester {
    private static final String TAG = "NonFrameworkPermissionTester";
    private final Logger mLogger = LoggerFactory.createActivityLogger(TAG,(LogListAdaptable) mActivity);

    private int mCntDRNEP=0;//DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
    public NonPlatformPermissionTester(TestConfiguration configuration, Activity activity) {
        super(configuration, activity);
    }

    @Override
    public boolean runPermissionTests() {
        boolean allTestsPassed = true;
        // Maintain a mapping of permissions to declaring packages; this way if a configuration
        // specifies a static list of permissions each permission can be looked up in expected
        // constant time.
        Map<String, String> permissionToPackage = new HashMap<>();
        List<PermissionInfo> declaredPermissions = PermissionUtils.getAllDeclaredPermissions(mContext);
        for (PermissionInfo permission : declaredPermissions) {
            // Ensure that the permission has signature protection level with no other
            // protection flags; the most common seen are privileged and preinstalled.
            if (!permission.packageName.equals(Constants.PLATFORM_PACKAGE)
                    && permission.getProtection() == PermissionInfo.PROTECTION_SIGNATURE
                    && permission.getProtectionFlags() == 0) {
                permissionToPackage.put(permission.name, permission.packageName);
            }
        }

        byte[] signatureBytes = mAppSignature.toByteArray();
        List<String> permissions = mConfiguration.getPermissions().orElse(
                new ArrayList<>(permissionToPackage.keySet()));
        // Maintain a mapping of each of the preloaded packages declaring signature permissions and
        // whether this app is signed by that package's signing key to minimize calls to
        // hasSigningCertificate.
        Map<String, Boolean> packageSignatureMatch = new HashMap<>();
        for (String permission : permissions) {
            // Only test those signature permissions that are declared on the device to avoid false
            // positives when the permission is expected to be granted.
            if (!permissionToPackage.containsKey(permission)) {
                mLogger.logDebug("Permission " + permission
                        + " is not declared by a non-platform package on this device");
                continue;
            }
            String packageName = permissionToPackage.get(permission);
            boolean signatureMatch;
            boolean permissionGranted = isPermissionGranted(permission);
            if (!packageSignatureMatch.containsKey(packageName)) {
                signatureMatch = mPackageManager.hasSigningCertificate(packageName,
                        signatureBytes, PackageManager.CERT_INPUT_RAW_X509);
                packageSignatureMatch.put(packageName, signatureMatch);
            } else {
                signatureMatch = Boolean.TRUE.equals(packageSignatureMatch.get(packageName));
            }
            if (permissionGranted != (signatureMatch || mPlatformSignatureMatch)) {
                allTestsPassed = false;
            }
            mLogger.logSignaturePermissionStatus(permission, permissionGranted, signatureMatch,
                    mPlatformSignatureMatch);
        }
        if (allTestsPassed) {
            mLogger.logInfo(
                    "*** PASSED - all non-framework signature permission tests completed "
                            + "successfully");
        } else {
            mLogger.logError(
                    "!!! FAILED - one or more non-framework signature permission tests failed");
        }
        return allTestsPassed;
    }

    public void runPermissionTestsByThreads(Consumer<Result> callback){
        Result.testerName = this.getClass().getSimpleName();

        //mLogger.logSystem(this.getClass().getSimpleName()+" not implemented runPermissionTestsByThreads yet");
// Maintain a mapping of permissions to declaring packages; this way if a configuration
        // specifies a static list of permissions each permission can be looked up in expected
        // constant time.
        Map<String, String> permissionToPackage = new HashMap<>();
        List<PermissionInfo> declaredPermissions = PermissionUtils.getAllDeclaredPermissions(mContext);
        for (PermissionInfo permission : declaredPermissions) {
            // Ensure that the permission has signature protection level with no other
            // protection flags; the most common seen are privileged and preinstalled.
            if (!permission.packageName.equals(Constants.PLATFORM_PACKAGE)
                    && permission.getProtection() == PermissionInfo.PROTECTION_SIGNATURE
                    && permission.getProtectionFlags() == 0) {
                permissionToPackage.put(permission.name, permission.packageName);
            }
        }

        byte[] signatureBytes = mAppSignature.toByteArray();
        List<String> permissions = mConfiguration.getPermissions().orElse(
                new ArrayList<>(permissionToPackage.keySet()));
        // Maintain a mapping of each of the preloaded packages declaring signature permissions and
        // whether this app is signed by that package's signing key to minimize calls to
        // hasSigningCertificate.
        Map<String, Boolean> packageSignatureMatch = new HashMap<>();
        //

        AtomicInteger cnt = new AtomicInteger(0);
        AtomicInteger err = new AtomicInteger(0);

        final int total = permissions.size();
        //There's no runnable test
        for (String permission : permissions) {

            // If the permission has a corresponding task then run it.
//            mLogger.logDebug("Starting test for non-platform permission: "+String.format(Locale.US,
//                    "%d/%d ",cnt.get(),total) + permission);



            Thread thread = new Thread(() -> {
                // Only test those signature permissions that are declared on the device to avoid false
                // positives when the permission is expected to be granted.
                String tester = this.getClass().getSimpleName();
                if (!permissionToPackage.containsKey(permission)) {
                    mLogger.logDebug("Permission " + permission
                            + " is not declared by a non-platform package on this device");
                    callback.accept(new Result(true, permission, aiIncl(cnt), total,err.get(),tester));
                    //continue;
                } else {
                    String packageName = permissionToPackage.get(permission);
                    boolean signatureMatch;
                    boolean permissionGranted = isPermissionGranted(permission);
                    if (!packageSignatureMatch.containsKey(packageName)) {
                        signatureMatch = mPackageManager.hasSigningCertificate(packageName,
                                signatureBytes, PackageManager.CERT_INPUT_RAW_X509);
                        packageSignatureMatch.put(packageName, signatureMatch);
                    } else {
                        signatureMatch = Boolean.TRUE.equals(packageSignatureMatch.get(packageName));
                    }
                    if (permissionGranted != (signatureMatch || mPlatformSignatureMatch)) {
                        if(permission.contains("DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")){
                            mCntDRNEP++;
                            mLogger.logDebug(permission+" is autogenerated permission by androidx. totalcount="+mCntDRNEP);
                            callback.accept(new Result(true, permission, aiIncl(cnt), total,err.get(),tester));
                        } else {
                            callback.accept(new Result(false, permission, aiIncl(cnt), total,aiIncl(err),tester));
                        }

                    } else {
                        callback.accept(new Result(true, permission, aiIncl(cnt), total,err.get(),tester));
                    }
                    mLogger.logSignaturePermissionStatus(permission, permissionGranted, signatureMatch,
                            mPlatformSignatureMatch);
                }
            });
            thread.start();
            try {
                thread.join(THREAD_JOIN_DELAY);
            } catch (InterruptedException e) {
                mLogger.logError(String.format(Locale.US,"%d %s failed due to the timeout.",cnt.get(),permission));
            }
        }
    }


    @Override
    public Map<String,PermissionTest> getRegisteredPermissions() {
        mLogger.logInfo("The Tester object handles all declared permissions. Ignored.");
        return new HashMap<String,PermissionTest>();
    }
}
