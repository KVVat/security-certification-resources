/*
 * Copyright 2021 The Android Open Source Project
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

import static android.Manifest.permission.ACCESS_FINE_LOCATION;
import static android.Manifest.permission.LAUNCH_CAPTURE_CONTENT_ACTIVITY_FOR_NOTE;
import static android.Manifest.permission.SCHEDULE_EXACT_ALARM;
import static android.content.Intent.ACTION_LAUNCH_CAPTURE_CONTENT_ACTIVITY_FOR_NOTE;
import static com.android.certifications.niap.permissions.utils.InternalPermissions.permission;
import static com.android.certifications.niap.permissions.utils.ReflectionUtils.invokeReflectionCall;
import static com.android.certifications.niap.permissions.utils.ReflectionUtils.stubHiddenObject;
import static com.android.certifications.niap.permissions.utils.ReflectionUtils.stubRemoteCallback;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlarmManager;
import android.app.KeyguardManager;
import android.app.PendingIntent;
import android.app.WallpaperManager;
import android.app.admin.DevicePolicyManager;
import android.app.admin.SystemUpdatePolicy;
import android.companion.AssociationRequest;
import android.companion.CompanionDeviceManager;
import android.content.AttributionSource;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.devicelock.IIsDeviceLockedCallback;
import android.devicelock._IIsDeviceLockedCallback;
import android.devicelock.ParcelableException;
import android.health.connect.aidl.IMigrationCallback;
import android.health.connect.migration.MigrationException;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.UserManager;
import android.provider.ContactsContract;
import android.view.WindowManager;

import androidx.annotation.NonNull;

import com.android.certifications.niap.permissions.activities.MainActivity;
import com.android.certifications.niap.permissions.activities.TestActivity;
import com.android.certifications.niap.permissions.config.TestConfiguration;
import com.android.certifications.niap.permissions.log.Logger;
import com.android.certifications.niap.permissions.log.LoggerFactory;
import com.android.certifications.niap.permissions.log.StatusLogger;
import com.android.certifications.niap.permissions.utils.ReflectionUtils;
import com.android.certifications.niap.permissions.utils.SignaturePermissions;
import com.android.certifications.niap.permissions.utils.SignatureUtils;
import com.android.certifications.niap.permissions.utils.TesterUtils;
import com.android.certifications.niap.permissions.utils.Transacts;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Collectors;


/**
 * Permission tester to verify all platform declared internal permissions properly guard their API,
 * resources, etc. An internal protection level permission is different from a signature permission
 * in that the requesting app will not be granted the permission just by being signed with the same
 * signing key as the platform, but instead must meet other requirements as defined by the
 * permission's flags.
 */
public class InternalPermissionTester extends BasePermissionTester {
    private static final String TAG = "InternalPermissionTester";
    private final Logger mLogger = LoggerFactory.createDefaultLogger(TAG);

    /**
     * Map of internal protection level permissions tto their corresponding {@link
     * PermissionTest}s.
     */
    private final Map<String, BasePermissionTester.PermissionTest> mPermissionTasks;

    public InternalPermissionTester(TestConfiguration configuration, Activity activity) {
        super(configuration, activity);


        mPermissionTasks = new HashMap<>();

        mPermissionTasks.put(permission.MANAGE_HOTWORD_DETECTION,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    try {
                        mTransacts.invokeTransact(Transacts.VOICE_INTERACTION_SERVICE,
                                Transacts.VOICE_INTERACTION_DESCRIPTOR, Transacts.updateState, null,
                                null, null);
                    } catch (SecurityException e) {
                        // Note, there are two places where this transact can throw a
                        // SecurityException; the first is during the permission check, the second
                        // is after the permission check is successful when determining if the
                        // current caller is the VoiceInteractionService. This could be flaky but
                        // treat the API as successful if the error message indicates the caller
                        // is not the VoiceInteractionService.
                        if (!e.getMessage().contains(
                                "Caller is not the current voice interaction service")) {
                            throw e;
                        } else {
                            mLogger.logDebug(
                                    "MANAGE_HOTWORD_DETECTION passed permission check, caught the"
                                            + " following exception: ", e);
                        }
                    }
                }));

        mPermissionTasks.put(permission.OBSERVE_SENSOR_PRIVACY,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    mTransacts.invokeTransact(Transacts.SENSOR_PRIVACY_SERVICE,
                            Transacts.SENSOR_PRIVACY_DESCRIPTOR, Transacts.isSensorPrivacyEnabled);
                }));

        mPermissionTasks.put(permission.DOMAIN_VERIFICATION_AGENT,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    mTransacts.invokeTransact(Transacts.DOMAIN_VERIFICATION_SERVICE,
                            Transacts.DOMAIN_VERIFICATION_DESCRIPTOR,
                            Transacts.queryValidVerificationPackageNames);
                }));

        mPermissionTasks.put(permission.ACCESS_RCS_USER_CAPABILITY_EXCHANGE,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    mTransacts.invokeTransact(Transacts.TELEPHONY_IMS_SERVICE,
                            Transacts.TELEPHONY_IMS_DESCRIPTOR, Transacts.requestAvailability, 0,
                            mPackageName, null,
                            null, null);
                }));

        mPermissionTasks.put(permission.ASSOCIATE_COMPANION_DEVICES,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    Signature signature = SignatureUtils.getTestAppSigningCertificate(mContext);
                    MessageDigest messageDigest;
                    try {
                        messageDigest = MessageDigest.getInstance("SHA-256");
                    } catch (NoSuchAlgorithmException e) {
                        throw new UnexpectedPermissionTestFailureException(e);
                    }
                    byte[] certDigest = messageDigest.digest(signature.toByteArray());
                    if (!mPackageManager.hasSigningCertificate(mPackageName, certDigest,
                            PackageManager.CERT_INPUT_SHA256)) {
                        throw new UnexpectedPermissionTestFailureException(
                                "PackageManager reported test app does not have the provided "
                                        + "signing certificate");
                    }
                    mTransacts.invokeTransact(Transacts.COMPANION_DEVICE_SERVICE,
                            Transacts.COMPANION_DEVICE_DESCRIPTOR, Transacts.createAssociation,
                            mPackageName, "11:22:33:44:55:66", 0, certDigest);
                }));

        mPermissionTasks.put(permission.BYPASS_ROLE_QUALIFICATION,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    mTransacts.invokeTransact(Transacts.ROLE_SERVICE, Transacts.ROLE_DESCRIPTOR,
                            Transacts.setBypassingRoleQualification, false);
                }));

        mPermissionTasks.put(permission.PERFORM_IMS_SINGLE_REGISTRATION,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    mTransacts.invokeTransact(Transacts.TELEPHONY_IMS_SERVICE,
                            Transacts.TELEPHONY_IMS_DESCRIPTOR,
                            Transacts.triggerNetworkRegistration, 0,
                            getActivityToken(), 0, "test-sip-reason");
                }));


        //Internal Permissions as of Android 13
        //permission.READ_ASSISTANT_APP_SEARCH_DATA depends on specific app role
        //permission.READ_HOME_APP_SEARCH_DATA depends on specific app role

        mPermissionTasks.put(permission.SET_DEFAULT_ACCOUNT_FOR_CONTACTS,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU, () -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        Bundle extras = new Bundle();
                        mContentResolver.call(ContactsContract.AUTHORITY_URI, "setDefaultAccount", null,
                                extras);
                        }
                }));

        mPermissionTasks.put(permission.SUBSCRIBE_TO_KEYGUARD_LOCKED_STATE,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU,
                        Build.VERSION_CODES.TIRAMISU, () -> {
                    //WindowManagerService#addKeyguardLockedStateListener.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        KeyguardManager.KeyguardLockedStateListener listener = new KeyguardManager.KeyguardLockedStateListener() {
                            @Override
                            public void onKeyguardLockedStateChanged(boolean b) {
                            }
                        };
                        mTransacts.invokeTransact(Transacts.WINDOW_SERVICE, Transacts.WINDOW_DESCRIPTOR,
                                Transacts.addKeyguardLockedStateListener, listener);
                    }
                }));

        mPermissionTasks.put(permission.CREATE_VIRTUAL_DEVICE,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU, () -> {
                    try {

                        Class<?> clazzVDPBuilder = null;
                        clazzVDPBuilder = Class.forName("android.companion.virtual.VirtualDeviceParams$Builder");
                        Constructor constructor = clazzVDPBuilder.getConstructor();
                        Object builderObj = constructor.newInstance();

                        Object vdpParams =
                                invokeReflectionCall(clazzVDPBuilder, "build", builderObj, new Class[]{});

                        IBinder binder = getActivityToken();
                        if(Build.VERSION.SDK_INT >= 35){
                            /* Parameters from SDK35
                            in IBinder token, in AttributionSource attributionSource, int associationId,
                            in VirtualDeviceParams params, in IVirtualDeviceActivityListener activityListener,
                            in IVirtualDeviceSoundEffectListener soundEffectListener
                            */
                            AttributionSource ats = new AttributionSource.Builder(0).build();
                            mTransacts.invokeTransact(Transacts.VIRTUAL_DEVICE_MANAGER_SERVICE,
                                    Transacts.VIRTUAL_DEVICE_MANAGER_DESCRIPTOR,
                                    Transacts.createVirtualDevice,
                                    binder,ats, 0,
                                    vdpParams,null,null);
                        } else {
                            mTransacts.invokeTransact(Transacts.VIRTUAL_DEVICE_MANAGER_SERVICE,
                                    Transacts.VIRTUAL_DEVICE_MANAGER_DESCRIPTOR,
                                    Transacts.createVirtualDevice,
                                    binder,mContext.getPackageName(), 0,
                                    vdpParams,null);
                        }

                    } catch (ClassNotFoundException | InvocationTargetException | NoSuchMethodException | IllegalAccessException | InstantiationException e) {
                        throw new UnexpectedPermissionTestFailureException(e);
                    }

                }));

        mPermissionTasks.put(permission.SEND_SAFETY_CENTER_UPDATE,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU, () -> {
                    Class<?> clazzSaftyCenter;
                    try {
                        clazzSaftyCenter = Class.forName("android.safetycenter.SafetyCenterManager");
                        Object saftyCenter = mContext.getSystemService(clazzSaftyCenter);
                        invokeReflectionCall
                                (clazzSaftyCenter, "getSafetySourceData",
                                        saftyCenter, new Class[]{String.class},"GooglePlaySystemUpdate");
                    } catch (ClassNotFoundException e){
                        throw new UnexpectedPermissionTestFailureException(e);
                    }
                })
        );

        mPermissionTasks.put(permission.REQUEST_COMPANION_PROFILE_AUTOMOTIVE_PROJECTION,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU, () -> {
                    if (!mPackageManager.hasSystemFeature(
                            PackageManager.FEATURE_COMPANION_DEVICE_SETUP)) {
                        throw new BypassTestException(
                                "Device does not have the "
                                        + "PackageManager#FEATURE_COMPANION_DEVICE_SETUP feature "
                                        + "for this test");
                    }
                    AssociationRequest request;
                    if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        request = new AssociationRequest.Builder().setDeviceProfile(
                                AssociationRequest.DEVICE_PROFILE_AUTOMOTIVE_PROJECTION).build();
                        CompanionDeviceManager.Callback callback =
                                new CompanionDeviceManager.Callback() {
                                    @Override
                                    public void onDeviceFound(IntentSender intentSender) {
                                        mLogger.logDebug(
                                                "onDeviceFound: intentSender = " + intentSender);
                                    }
                                    @Override
                                    public void onFailure(CharSequence charSequence) {
                                        mLogger.logDebug("onFailure: charSequence = " + charSequence);
                                    }
                                };
                        CompanionDeviceManager companionDeviceManager = mActivity.getSystemService(
                                CompanionDeviceManager.class);

                        companionDeviceManager.associate(request, callback, null);
                    }

                }));

        //Move to Signature Permission from U
        mPermissionTasks.put(permission.ACCESS_AMBIENT_CONTEXT_EVENT,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU,
                        Build.VERSION_CODES.TIRAMISU, () -> {

                    @SuppressLint("WrongConstant") Object ambientContextManager
                            = mContext.getSystemService("ambient_context");
                            //Context.AMBIENT_CONTEXT_SERVICE);

                    int[] eventsArray = new int[] {-1};//AmbientContextEvent.EVENT_COUGH
                    Set<Integer> eventTypes = Arrays.stream(eventsArray).boxed().collect(
                            Collectors.toSet());

                    invokeReflectionCall(ambientContextManager.getClass(),
                            "queryAmbientContextServiceStatus",
                            ambientContextManager, new Class[]{Set.class, Executor.class,
                                    Consumer.class}, eventTypes, new Executor() {
                                @Override
                                public void execute(Runnable runnable) {

                                }
                            }, null);

                }));

        // # Skip READ_ASSISTANT_APP_SEARCH_DATA
        //Reason : Need specific role to test this permission.

        // # Skip READ_HOME_APP_SEARCH_DATA
        //Reason : Need specific role to test this permission.

        mPermissionTasks.put(permission.MANAGE_SAFETY_CENTER,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU,() -> {
                    mTransacts.invokeTransact(Transacts.SAFETY_CENTER_MANAGER_SERVICE,
                            Transacts.SAFETY_CENTER_MANAGER_MANAGER_DESCRIPTOR,
                            Transacts.getSafetyCenterConfig);
                }));

        //The permission is moved from signature permission (since android s)
        mPermissionTasks.put(SignaturePermissions.permission.MANAGE_SENSOR_PRIVACY,
                new PermissionTest(false, Build.VERSION_CODES.S,() -> {
                    // ISensorPrivacyManager#setSensorPrivacy
                    mTransacts.invokeTransact(Transacts.SENSOR_PRIVACY_SERVICE,
                            Transacts.SENSOR_PRIVACY_DESCRIPTOR,
                            Transacts.setSensorPrivacy, false);
                }));

        //The permission is moved from signature permission (since android t)
        mPermissionTasks.put(SignaturePermissions.permission.TOGGLE_AUTOMOTIVE_PROJECTION,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU, () -> {
                    mTransacts.invokeTransact(Transacts.UI_MODE_SERVICE,
                            Transacts.UI_MODE_DESCRIPTOR, Transacts.requestProjection,
                            getActivityToken(), 1, mPackageName);

                    /*mActivity.sendBroadcast(
                            new Intent("android.intent.action.ACTION_USER_UNLOCKED"));*/
                }));



        //Android 14 Implementations//

        mPermissionTasks.put(permission.READ_RESTRICTED_STATS,
                new PermissionTest(false, Build.VERSION_CODES.UPSIDE_DOWN_CAKE, () -> {
                    if (android.os.Build.VERSION.SDK_INT >= 34) {

                        String STATS_MANAGER = "statsmanager";

                        Intent i = new Intent(mContext, TestActivity.class);
                        PendingIntent pendingIntent = PendingIntent.getActivity(mContext, 0, i, PendingIntent.FLAG_IMMUTABLE);

                        mTransacts.invokeTransact(
                                STATS_MANAGER,
                                Transacts.STATS_DESCRIPTOR,
                                Transacts.setRestrictedMetricsChangedOperation,
                                pendingIntent,1L ,mContext.getPackageName()
                        );
                    }
                }));



        mPermissionTasks.put(permission.LAUNCH_CAPTURE_CONTENT_ACTIVITY_FOR_NOTE,
                new PermissionTest(false, Build.VERSION_CODES.UPSIDE_DOWN_CAKE, () -> {
                    //commonize the tester routine with exposing the builder of AssociationRequest object
                    if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        Intent featuresIntent = new Intent(ACTION_LAUNCH_CAPTURE_CONTENT_ACTIVITY_FOR_NOTE)
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        final PackageManager mgr = mContext.getPackageManager();

                        featuresIntent.setComponent(new
                                ComponentName("com.android.systemui",
                                "com.android.systemui.screenshot.appclips.AppClipsService"));

                        List<ResolveInfo> list =
                                mgr.queryIntentActivities(featuresIntent,
                                        PackageManager.MATCH_DEFAULT_ONLY);
                        if(list.size()>0){
                            mActivity.startActivity(featuresIntent);
                        } else {
                            throw new BypassTestException("AppClipService doesn't exist in this device.");
                        }

                    }
                }));

        mPermissionTasks.put(permission.MANAGE_DEVICE_LOCK_STATE,
                new PermissionTest(false, Build.VERSION_CODES.UPSIDE_DOWN_CAKE, () -> {
                    CountDownLatch latch = new CountDownLatch(1);
                    AtomicBoolean success = new AtomicBoolean(true);

                    //need below command to execute this test case
                    //adb shell settings put global hidden_api_policy  1

                    //mLogger.logSystem("aaa>"+android.os.Build.VERSION.SDK_INT);
                    if(android.os.Build.VERSION.SDK_INT >= 35) {
                        //mLogger.logSystem("aaa");
                        //Interface Change
                        IIsDeviceLockedCallback callback = new IIsDeviceLockedCallback() {
                            @Override
                            public void onIsDeviceLocked(boolean locked) throws RemoteException {
                                //mLogger.logSystem("onError1");
                            }

                            @Override
                            public void onError(ParcelableException ex) throws RemoteException {
                                //mLogger.logSystem("onError");
                            }

                            @Override
                            public IBinder asBinder() {
                                return new IIsDeviceLockedCallback.Stub() {

                                    @Override
                                    public void onIsDeviceLocked(boolean locked) throws RemoteException {
                                        //mLogger.logSystem("-onError2");

                                        latch.countDown();
                                    }

                                    @Override
                                    public void onError(ParcelableException ex) throws RemoteException {
                                        //mLogger.logSystem("-onError");

                                        if(ex.getException().toString().equals("java.lang.SecurityException")){
                                            success.set(false);
                                        }
                                        latch.countDown();
                                    }
                                };
                            }
                        };
                        try {
                            //MANAGE_DEVICE_LOCK_STATE
                            mTransacts.invokeTransact(
                                    Context.DEVICE_LOCK_SERVICE,
                                    Transacts.DEVICELOCK_DESCRIPTOR,
                                    Transacts.isDeviceLocked,callback);

                            latch.await(2000, TimeUnit.MILLISECONDS);
                            if(!success.get()){
                                throw new SecurityException("Found secuirty error in callback interface!");
                            }
                        } catch (InterruptedException e) {
                            mLogger.logError(e.getMessage(),e);
                        }
                    }else if (android.os.Build.VERSION.SDK_INT == Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        // NOTICE:
                        // We can not use an interface with a same name at once, so if you would like to test it
                        // with SDK34 kindly change name of these callbacks.
                        _IIsDeviceLockedCallback callback = new _IIsDeviceLockedCallback() {
                            @Override
                            public void onIsDeviceLocked(boolean locked) throws RemoteException {

                            }

                            @Override
                            public void onError(int error) throws RemoteException {

                            }

                            @Override
                            public IBinder asBinder() {
                                return new _IIsDeviceLockedCallback.Stub() {

                                    @Override
                                    public void onIsDeviceLocked(boolean locked) throws RemoteException {

                                        latch.countDown();
                                    }

                                    @Override
                                    public void onError(int error) throws RemoteException {

                                        if (_IIsDeviceLockedCallback.ERROR_SECURITY == error) {
                                            success.set(false);
                                        }
                                        latch.countDown();
                                    }
                                };
                            }
                        };
                        try {

                            //MANAGE_DEVICE_LOCK_STATE
                            mTransacts.invokeTransact(
                                Context.DEVICE_LOCK_SERVICE,
                                Transacts.DEVICELOCK_DESCRIPTOR,
                                Transacts.isDeviceLocked,callback);

                            latch.await(2000, TimeUnit.MILLISECONDS);
                            if(!success.get()){
                                throw new SecurityException("Found secuirty error in callback interface!");
                            }
                        } catch (InterruptedException e) {
                            mLogger.logError(e.getMessage());
                            e.printStackTrace();
                        }
                    }
                }));

        // New internal permissions as of Android 15

        mPermissionTasks.put(permission.QUERY_DEVICE_STOLEN_STATE,
                new PermissionTest(false, Build.VERSION_CODES.UPSIDE_DOWN_CAKE, () -> {
                    if(!TesterUtils.getAdminFlagByName("deviceTheftImplEnabled")){
                        throw new BypassTestException(
                                "To run this test, deviceTheftImplEnabled system flag should be enabled.Aborted");
                    }
                    mTransacts.invokeTransact(
                            Transacts.DEVICE_POLICY_SERVICE,
                            Transacts.DEVICE_POLICY_DESCRIPTOR,
                            Transacts.isDevicePotentiallyStolen,mPackageName);

                }));

        /*
        mPermissionTasks.put(permission.EMBED_ANY_APP_IN_UNTRUSTED_MODE,
                new PermissionTest(false, Build.VERSION_CODES.UPSIDE_DOWN_CAKE, () -> {
                    mLogger.logDebug("Test case for android.permission.EMBED_ANY_APP_IN_UNTRUSTED_MODE not implemented yet");
                   /* ReflectionUtils.
                    final TaskFragment taskFragment = new TaskFragmentBuilder(mAtm)
                            .setCreateParentTask()
                            .createActivityCount(1)
                            .build();
                    //final ActivityRecord activity = taskFragment.getTopMostActivity();
                }));
        */
        /////////////////////////////////////////////////////////////////////
        //permission.ALWAYS_UPDATE_WALLPAPER is infeasible to test, because the
        //WindowsSession.mCanAlwaysUpdateWallpaper is not exposed to users


    }

    @Override
    public boolean runPermissionTests() {
        boolean allTestsPassed = true;
        List<String> permissions = mConfiguration.getInternalPermissions().orElse(
                new ArrayList<>(mPermissionTasks.keySet()));

        for (String permission : permissions) {
            BasePermissionTester.PermissionTest t = mPermissionTasks.get(permission);
            boolean testPassed = true;
            //System.out.println(permission+","+mPermissionTasks.size()+"/"+t);
            if(t != null) {
                testPassed = runPermissionTest(permission, mPermissionTasks.get(permission),
                        true);
            } else {
                testPassed = false;
                //mLogger.logInfo(permission+","+mPermissionTasks.size()+"/"+mPermissionTasks.keySet().toString());
                mLogger.logInfo(
                        "The test case for "+permission+" is not found");
            }
            if (!testPassed) {
                allTestsPassed = false;
            }
        }
        if (allTestsPassed) {
            mLogger.logInfo(
                    "*** PASSED - all internal permission tests completed successfully");
        } else {
            mLogger.logInfo(
                    "!!! FAILED - one or more internal permission tests failed");
        }
        return allTestsPassed;
    }
    public void runPermissionTestsByThreads(androidx.core.util.Consumer<Result> callback){
        Result.testerName = this.getClass().getSimpleName();

        List<String> permissions = mConfiguration.getInternalPermissions().orElse(
                new ArrayList<>(mPermissionTasks.keySet()));

        int no=0;
        AtomicInteger cnt = new AtomicInteger(0);
        AtomicInteger err = new AtomicInteger(0);
        final int total = permissions.size();
        for (String permission : permissions) {
            String tester = this.getClass().getSimpleName();
            Thread thread = new Thread(() -> {
                if (runPermissionTest(permission, mPermissionTasks.get(permission), true)) {
                    callback.accept(new Result(true, permission, aiIncl(cnt), total,err.get(),tester));
                } else {
                    callback.accept(new Result(false, permission, aiIncl(cnt), total,aiIncl(err),tester));
                }
            });
            thread.start();
            try {
                thread.join(THREAD_JOIN_DELAY);
            } catch (InterruptedException e) {
                mLogger.logError(String.format(Locale.US,"%d %s failed due to the timeout.",no,permission));
            }
        }
    }

    @Override
    public Map<String,PermissionTest> getRegisteredPermissions() {
        return mPermissionTasks;
    }

    /**
     * Returns the {@link IBinder} token for the current activity.
     *
     * <p>This token can be used in any binder transaction that requires the activity's token.
     */
    public IBinder getActivityToken() {
        try {
            Field tokenField = Activity.class.getDeclaredField("mToken");
            tokenField.setAccessible(true);
            return (IBinder) tokenField.get(mActivity);
        } catch (ReflectiveOperationException e) {
            throw new UnexpectedPermissionTestFailureException(e);
        }
    }
}


