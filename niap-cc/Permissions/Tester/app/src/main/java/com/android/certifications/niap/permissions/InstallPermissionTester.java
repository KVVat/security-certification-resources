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

import static android.Manifest.permission.ACCESS_NETWORK_STATE;
import static android.Manifest.permission.ACCESS_WIFI_STATE;
import static android.Manifest.permission.BLUETOOTH;
import static android.Manifest.permission.BLUETOOTH_ADMIN;
import static android.Manifest.permission.BROADCAST_STICKY;
import static android.Manifest.permission.CHANGE_NETWORK_STATE;
import static android.Manifest.permission.CHANGE_WIFI_MULTICAST_STATE;
import static android.Manifest.permission.CHANGE_WIFI_STATE;
import static android.Manifest.permission.CREDENTIAL_MANAGER_QUERY_CANDIDATE_CREDENTIALS;
import static android.Manifest.permission.CREDENTIAL_MANAGER_SET_ALLOWED_PROVIDERS;
import static android.Manifest.permission.CREDENTIAL_MANAGER_SET_ORIGIN;
import static android.Manifest.permission.DETECT_SCREEN_CAPTURE;
import static android.Manifest.permission.DETECT_SCREEN_RECORDING;
import static android.Manifest.permission.DISABLE_KEYGUARD;
import static android.Manifest.permission.ENFORCE_UPDATE_OWNERSHIP;
import static android.Manifest.permission.EXPAND_STATUS_BAR;
import static android.Manifest.permission.FOREGROUND_SERVICE;
import static android.Manifest.permission.FOREGROUND_SERVICE_CAMERA;
import static android.Manifest.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE;
import static android.Manifest.permission.FOREGROUND_SERVICE_DATA_SYNC;
import static android.Manifest.permission.FOREGROUND_SERVICE_HEALTH;
import static android.Manifest.permission.FOREGROUND_SERVICE_LOCATION;
import static android.Manifest.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK;
import static android.Manifest.permission.FOREGROUND_SERVICE_MEDIA_PROCESSING;
import static android.Manifest.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION;
import static android.Manifest.permission.FOREGROUND_SERVICE_MICROPHONE;
import static android.Manifest.permission.FOREGROUND_SERVICE_PHONE_CALL;
import static android.Manifest.permission.FOREGROUND_SERVICE_REMOTE_MESSAGING;
import static android.Manifest.permission.FOREGROUND_SERVICE_SPECIAL_USE;
import static android.Manifest.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED;
import static android.Manifest.permission.HIDE_OVERLAY_WINDOWS;
import static android.Manifest.permission.INTERNET;
import static android.Manifest.permission.KILL_BACKGROUND_PROCESSES;
import static android.Manifest.permission.MANAGE_OWN_CALLS;
import static android.Manifest.permission.MODIFY_AUDIO_SETTINGS;
import static android.Manifest.permission.NFC;
import static android.Manifest.permission.NFC_PREFERRED_PAYMENT_INFO;
import static android.Manifest.permission.QUERY_ALL_PACKAGES;
import static android.Manifest.permission.READ_BASIC_PHONE_STATE;
import static android.Manifest.permission.READ_NEARBY_STREAMING_POLICY;
import static android.Manifest.permission.READ_SYNC_SETTINGS;
import static android.Manifest.permission.READ_SYNC_STATS;
import static android.Manifest.permission.REORDER_TASKS;
import static android.Manifest.permission.REQUEST_COMPANION_PROFILE_GLASSES;
import static android.Manifest.permission.REQUEST_COMPANION_PROFILE_WATCH;
import static android.Manifest.permission.REQUEST_DELETE_PACKAGES;
import static android.Manifest.permission.REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE;
import static android.Manifest.permission.REQUEST_PASSWORD_COMPLEXITY;
import static android.Manifest.permission.RUN_USER_INITIATED_JOBS;
import static android.Manifest.permission.SCHEDULE_EXACT_ALARM;
import static android.Manifest.permission.SET_WALLPAPER;
import static android.Manifest.permission.SET_WALLPAPER_HINTS;
import static android.Manifest.permission.TRANSMIT_IR;
import static android.Manifest.permission.USE_BIOMETRIC;
import static android.Manifest.permission.USE_EXACT_ALARM;
import static android.Manifest.permission.USE_FULL_SCREEN_INTENT;
import static android.Manifest.permission.VIBRATE;
import static android.Manifest.permission.WAKE_LOCK;
import static android.Manifest.permission.WRITE_SYNC_SETTINGS;
import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
import static android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED;
import static com.android.certifications.niap.permissions.Constants.EXTRA_PERMISSION_GRANTED;
import static com.android.certifications.niap.permissions.Constants.EXTRA_PERMISSION_NAME;
import static com.android.certifications.niap.permissions.utils.ReflectionUtils.invokeReflectionCall;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.AlarmManager;
import android.app.KeyguardManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.WallpaperManager;
import android.app.admin.DevicePolicyManager;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.companion.AssociationRequest;
import android.companion.CompanionDeviceManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.LauncherApps;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.VersionedPackage;
import android.content.res.Resources;
import android.graphics.Rect;
import android.hardware.ConsumerIrManager;
import android.hardware.biometrics.BiometricManager;
import android.hardware.fingerprint.FingerprintManager;
import android.media.AudioManager;
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.nfc.NfcAdapter;
import android.nfc.cardemulation.CardEmulation;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.os.RemoteException;
import android.os.UserHandle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.service.notification.StatusBarNotification;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import android.telephony.TelephonyManager;
import android.window.IScreenRecordingCallback;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.ActivityCompat;
import androidx.core.util.Consumer;
import androidx.credentials.CreateCredentialRequest;
import androidx.credentials.CredentialManager;
import androidx.credentials.CredentialManagerCallback;
import androidx.credentials.CredentialOption;
import androidx.credentials.GetCredentialRequest;
import androidx.credentials.GetCredentialResponse;
import androidx.credentials.GetPublicKeyCredentialOption;
import androidx.credentials.PasswordCredential;
import androidx.credentials.PrepareGetCredentialResponse;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.test.runner.screenshot.Screenshot;

import com.android.certifications.niap.permissions.activities.LogListAdaptable;
import com.android.certifications.niap.permissions.activities.MainActivity;
import com.android.certifications.niap.permissions.activities.TestActivity;
import com.android.certifications.niap.permissions.companion.services.TestBindService;
import com.android.certifications.niap.permissions.config.TestConfiguration;
import com.android.certifications.niap.permissions.log.Logger;
import com.android.certifications.niap.permissions.log.LoggerFactory;
import com.android.certifications.niap.permissions.services.FgCameraService;
import com.android.certifications.niap.permissions.services.FgConnectedDeviceService;
import com.android.certifications.niap.permissions.services.FgDataSyncService;
import com.android.certifications.niap.permissions.services.FgHealthService;
import com.android.certifications.niap.permissions.services.FgLocationService;
import com.android.certifications.niap.permissions.services.FgMediaPlaybackService;
import com.android.certifications.niap.permissions.services.FgMediaProcessingService;
import com.android.certifications.niap.permissions.services.FgMediaProjectionService;
import com.android.certifications.niap.permissions.services.FgMicrophoneService;
import com.android.certifications.niap.permissions.services.FgPhoneCallService;
import com.android.certifications.niap.permissions.services.FgRemoteMessagingService;
import com.android.certifications.niap.permissions.services.FgSpecialUseService;
import com.android.certifications.niap.permissions.services.FgSystemExemptedService;
import com.android.certifications.niap.permissions.services.TestJobService;
import com.android.certifications.niap.permissions.services.TestService;
import com.android.certifications.niap.permissions.utils.ReflectionUtils;
import com.android.certifications.niap.permissions.utils.TesterUtils;
import com.android.certifications.niap.permissions.utils.Transacts;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import javax.security.auth.callback.PasswordCallback;

/**
 * Permission tester to verify all install permissions properly guard their API, resource, etc.
 * Install permissions only need to be requested using the {@code <uses-permission>} tag in the
 * {@code AndroidManifest.xml} and will be granted upon install.
 */
public class InstallPermissionTester extends BasePermissionTester {
    private static final String TAG = "InstallPermissionTester";
    private final Logger mLogger = LoggerFactory.createActivityLogger(TAG,(LogListAdaptable)mActivity);

    protected final ConnectivityManager mConnectivityManager;
    protected final WifiManager mWifiManager;
    protected final BluetoothAdapter mBluetoothAdapter;
    protected final BluetoothManager mBluetoothManager;
    protected final KeyguardManager mKeyguardManager;
    protected final ActivityManager mActivityManager;
    protected final AudioManager mAudioManager;
    protected final PackageInstaller mPackageInstaller;
    protected final DevicePolicyManager mDevicePolicyManager;
    protected final WallpaperManager mWallpaperManager;
    protected final ConsumerIrManager mConsumerIrManager;
    protected final Vibrator mVibrator;
    protected final PowerManager mPowerManager;

    private final ExecutorService mExecutorService;
    private final Map<String, PermissionTest> mPermissionTasks;

    public InstallPermissionTester(TestConfiguration configuration, Activity activity) {
        super(configuration, activity);

        mConnectivityManager = (ConnectivityManager) mContext.getSystemService(
                Context.CONNECTIVITY_SERVICE);
        mWifiManager = (WifiManager) mContext.getSystemService(Context.WIFI_SERVICE);
        mBluetoothManager = (BluetoothManager) mContext.getSystemService(Context.BLUETOOTH_SERVICE);
        mBluetoothAdapter = mBluetoothManager.getAdapter();
        mKeyguardManager = (KeyguardManager) mContext.getSystemService(Context.KEYGUARD_SERVICE);
        mActivityManager = (ActivityManager) mContext.getSystemService(Context.ACTIVITY_SERVICE);
        mAudioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
        mPackageInstaller = mPackageManager.getPackageInstaller();
        mDevicePolicyManager = (DevicePolicyManager) mContext.getSystemService(
                Context.DEVICE_POLICY_SERVICE);
        mWallpaperManager = (WallpaperManager) mContext.getSystemService(Context.WALLPAPER_SERVICE);
        mConsumerIrManager = (ConsumerIrManager) mContext.getSystemService(
                Context.CONSUMER_IR_SERVICE);
        mVibrator = (Vibrator) mContext.getSystemService(Context.VIBRATOR_SERVICE);
        mPowerManager = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);

        mExecutorService = ((TesterApplication)mActivity.getApplication()).executorService;

        mPermissionTasks = new HashMap<>();

        mPermissionTasks.put(ACCESS_NETWORK_STATE,
                new PermissionTest(false, () -> mConnectivityManager.getActiveNetwork()));

        mPermissionTasks.put(ACCESS_WIFI_STATE,
                new PermissionTest(false, () -> {
                    if (ActivityCompat.checkSelfPermission(mContext, Manifest.permission.ACCESS_FINE_LOCATION)
                            != PackageManager.PERMISSION_GRANTED) {
                        throw new BypassTestException(
                                "ACCESS_FINLE_LOCATION permission should be granted to run this test case");
                    }
                    mWifiManager.getConfiguredNetworks();

                }));

        // android.permission.AUTHENTICATE_ACCOUNTS has been removed.

        // Starting in Android 12 the install BLUETOOTH permission is no longer used and has instead
        // been replaced by the new runtime BLUETOOTH permissions.
        mPermissionTasks.put(BLUETOOTH,
                new PermissionTest(false, Build.VERSION_CODES.P, Build.VERSION_CODES.R, () -> {
                    if (mBluetoothAdapter == null) {
                        throw new BypassTestException(
                                "A bluetooth adapter is not available to run this test");
                    }
                    mBluetoothAdapter.getAddress();
                }));

        // Starting in Android 12 the BLUETOOTH_ADMIN permission is no longer used and has instead
        // been replaced by the new runtime BLUETOOTH permissions.
        mPermissionTasks.put(BLUETOOTH_ADMIN,
                new PermissionTest(false, Build.VERSION_CODES.P, Build.VERSION_CODES.R, () -> {
                    if (mBluetoothAdapter == null) {
                        throw new BypassTestException(
                                "A bluetooth adapter is not available to run this test");
                    }
                    if (mBluetoothAdapter.isEnabled()) {
                        mBluetoothAdapter.disable();
                        mBluetoothAdapter.enable();
                    } else {
                        mBluetoothAdapter.enable();
                    }
        }));

        mPermissionTasks.put(BROADCAST_STICKY, new PermissionTest(false, () -> {
            Intent intent = new Intent();
            mContext.sendStickyBroadcast(intent);
        }));

        // android.permission.CALL_COMPANION_APP requires an active call.

        mPermissionTasks.put(CHANGE_NETWORK_STATE, new PermissionTest(false, () -> {
            NetworkRequest networkRequest = new NetworkRequest.Builder().addCapability(
                    NET_CAPABILITY_INTERNET).build();
            mConnectivityManager.requestNetwork(networkRequest, new NetworkCallback() {
                @Override
                public void onAvailable(Network network) {
                }
            });
        }));

        mPermissionTasks.put(CHANGE_WIFI_MULTICAST_STATE, new PermissionTest(false, () -> {
            WifiManager.MulticastLock multicastLock = mWifiManager.createMulticastLock(TAG);
            multicastLock.acquire();
            multicastLock.release();
        }));

        mPermissionTasks
                .put(CHANGE_WIFI_STATE,
                        new PermissionTest(false, () -> mWifiManager.setWifiEnabled(true)));

        mPermissionTasks.put(DISABLE_KEYGUARD, new PermissionTest(false, () -> {
            KeyguardManager.KeyguardLock keyguardLock = mKeyguardManager.newKeyguardLock(TAG);
            keyguardLock.disableKeyguard();
        }));

        //TODO:This Test Action Hide Screen
        mPermissionTasks.put(EXPAND_STATUS_BAR, new PermissionTest(false, () -> {

            if(Constants.BYPASS_TESTS_AFFECTING_UI)
                throw new BypassTestException("This test case affects to UI. skip to avoiding ui stuck.");

            @SuppressLint("WrongConstant") Object statusBarManager = mContext.getSystemService("statusbar");

            invokeReflectionCall(statusBarManager.getClass(), "expandNotificationsPanel",
                    statusBarManager, null);
            // A short sleep is required to allow the notification panel to be expanded before
            // collapsing it to clean up after this test.
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                mLogger.logDebug("Caught an InterruptedException: ", e);
            }
            // Starting in Android 12 this API is no longer available without the signature
            // permission STATUS_BAR.
            if (mDeviceApiLevel < Build.VERSION_CODES.S) {
                invokeReflectionCall(statusBarManager.getClass(), "collapsePanels",
                        statusBarManager, null);
            }
        }));

        // andorid.permission.FLASHLIGHT has been removed.

        //The test doesn't work after U, because foreground services requests corresponding type permission now.
        mPermissionTasks.put(FOREGROUND_SERVICE, new PermissionTest(true,Build.VERSION_CODES.P,
                Build.VERSION_CODES.TIRAMISU, () -> {
            // This test must run as a custom test because it requires a separate service be run in
            // in the foreground that can invoke startForeground.
            String permission = FOREGROUND_SERVICE;
            boolean permissionGranted = isPermissionGranted(permission);
            try {
                Intent serviceIntent = new Intent(mContext, TestService.class);
                serviceIntent.putExtra(EXTRA_PERMISSION_NAME, permission);
                serviceIntent.putExtra(EXTRA_PERMISSION_GRANTED, permissionGranted);
                mContext.startForegroundService(serviceIntent);
            } catch (Throwable t) {
                mLogger.logTestError(permission, t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_CAMERA,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgCameraService.class);
            try {
                mActivity.startForegroundService(serviceIntent);

                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_CAMERA", t);

            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_LOCATION,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgLocationService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_LOCATION", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_MICROPHONE,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgMicrophoneService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_MICROPHONE", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_CONNECTED_DEVICE,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgConnectedDeviceService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_CONNECTED_DEVICE", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_DATA_SYNC,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgDataSyncService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_DATA_SYNC", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_HEALTH,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgHealthService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_HEALTH", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_MEDIA_PLAYBACK,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgMediaPlaybackService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_MEDIA_PLAYBACK", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_MEDIA_PROJECTION,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgMediaProjectionService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_MEDIA_PROJECTION", t);
            }
        }));

        mPermissionTasks.put(FOREGROUND_SERVICE_PHONE_CALL,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgPhoneCallService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_PHONE_CALL", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_REMOTE_MESSAGING,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgRemoteMessagingService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_REMOTE_MESSAGING", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_SPECIAL_USE,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgSpecialUseService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_SPECIAL_USE", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_SYSTEM_EXEMPTED,  new PermissionTest(true,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            Intent serviceIntent = new Intent(mActivity, FgSystemExemptedService.class);
            try {
                mActivity.startForegroundService(serviceIntent);
                tryBindingForegroundService(serviceIntent);
            } catch(Throwable t){
                mLogger.logDebug("FOREGROUND_SERVICE_SYSTEM_EXEMPTED", t);
            }
        }));
        mPermissionTasks.put(FOREGROUND_SERVICE_MEDIA_PROCESSING,
                new PermissionTest(true, Build.VERSION_CODES.UPSIDE_DOWN_CAKE, () -> {
                ///New Foreground Service Permission
                Intent serviceIntent = new Intent(mActivity, FgMediaProcessingService.class);
                try {
                    mActivity.startForegroundService(serviceIntent);
                    tryBindingForegroundService(serviceIntent);
                } catch(Throwable t){
                    mLogger.logDebug("FOREGROUND_SERVICE_MEDIA_PROCESSING", t);
                }
            }));

        // android.permission.GET_PACKAGE_SIZE only guards PackageManager#getPackageSizeInfoAsUser
        // which is hidden and results in an UnsupportedOperationException after O.

        // android.permission.GET_TASKS has been deprecated and is no longer enforced.

        // android.permission.INSTALL_SHORTCUT is no longer used.

        mPermissionTasks.put(INTERNET, new PermissionTest(false, () -> {
            try {
                // Use a simple ServerSocket with a value of 0 to pick a free port to verify the
                // Internet permission.
                ServerSocket socket = new ServerSocket(0);
                socket.close();
            } catch (Throwable t) {
                // Sockets that require the Internet permission will not throw SecurityExceptions
                // but instead will throw SocketExceptions with a message containing EACCES
                // (Permission Denied).
                // NOTE: Later versions of the platform also return an EPERM error for this case.
                if (t instanceof SocketException && (t.getMessage().contains("EACCES")
                        || t.getMessage().contains("EPERM"))) {
                    throw new SecurityException(t);
                } else {
                    throw new UnexpectedPermissionTestFailureException(t);
                }
            }
        }));

        mPermissionTasks.put(KILL_BACKGROUND_PROCESSES, new PermissionTest(false,
                () -> mActivityManager.killBackgroundProcesses(Constants.COMPANION_PACKAGE)));

        // android.permission.MANAGE_ACCOUNTS has been removed.

        mPermissionTasks.put(MODIFY_AUDIO_SETTINGS, new PermissionTest(false, () -> {
            // This API does not throw a SecurityException but instead just logs a permission denial
            // similar to the following in logcat:
            // AS.AudioService: Audio Settings Permission Denial: setMicrophoneMute() from
            //     pid=26925, uid=10250
            boolean micMuted = mAudioManager.isMicrophoneMute();
            mAudioManager.setMicrophoneMute(!micMuted);
            if (mAudioManager.isMicrophoneMute() == micMuted) {
                throw new SecurityException("mic mute status could not be changed");
            }
            // restore the mic mute status to the original setting
            mAudioManager.setMicrophoneMute(micMuted);
        }));

        mPermissionTasks.put(MANAGE_OWN_CALLS, new PermissionTest(false, () -> {
            TelecomManager telecomManager = (TelecomManager) mContext.getSystemService(
                    Context.TELECOM_SERVICE);
            Uri numberUri = Uri.fromParts(PhoneAccount.SCHEME_TEL, "886", null);
            telecomManager.addNewIncomingCall(null, null);
            PhoneAccountHandle phoneAccountHandle = new PhoneAccountHandle(
                    new ComponentName(mContext, MainActivity.class), "TestId");
            telecomManager.isIncomingCallPermitted(phoneAccountHandle);
        }));

        mPermissionTasks.put(NFC, new PermissionTest(false, () -> {
            // SELinux blocks access to the NFC service from platform apps, so skip this test if the
            // app is platform signed.
            // SELinux : avc:  denied  { find } for service=nfc pid=24835 uid=10144
            //     scontext=u:r:platform_app:s0:c512,c768 tcontext=u:object_r:nfc_service:s0
            //     tclass=service_manager permissive=0
            // NFC     : could not retrieve NFC service
            NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
            if (adapter == null) {
                throw new BypassTestException("An NFC adapter is not available to run this test");
            }
            //:TODO setNdefPushMesssage is obsolated?
            //adapter.setNdefPushMessage(null, mActivity);

            CardEmulation emulation = CardEmulation.getInstance(adapter);
            emulation.isDefaultServiceForCategory(new ComponentName(mContext, TestService.class),
                    CardEmulation.CATEGORY_PAYMENT);
        }));

        // android.permission.NFC_TRANSACTION_EVENT only guards broadcasts during NFC transactions.

        // android.permission.PERSISTENT_ACTIVITY is no longer used.

        // android.permission.READ_HISTORY_BOOKMARKS has been removed.

        // android.permission.READ_INSTALL_SESSIONS is no longer used.

        // android.permission.READ_PROFILE has been removed.

        // android.permission.READ_SOCIAL_STREAM has been removed.

        mPermissionTasks.put(READ_SYNC_SETTINGS,
                new PermissionTest(false, () -> ContentResolver.getMasterSyncAutomatically()));

        mPermissionTasks
                .put(READ_SYNC_STATS,
                        new PermissionTest(false, () -> ContentResolver.getCurrentSyncs()));

        // android.permission.READ_USER_DICTIONARY has been removed.

        // android.permission.RECEIVE_BOOT_COMPLETED only guards receiving the boot
        // completed broadcast.

        mPermissionTasks.put(REORDER_TASKS,
                new PermissionTest(false, () -> mActivityManager.moveTaskToFront(2, 0)));

        // android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND requires companion device
        // with which to associate this app.

        // android.permission.REQUEST_COMPANION_USE_DATA_IN_BACKGROUND requires companion device
        // with which to associate this app.

        mPermissionTasks.put(REQUEST_DELETE_PACKAGES, new PermissionTest(false, () -> {
            Intent intent = new Intent(mActivity, TestActivity.class);
            PendingIntent pendingIntent = PendingIntent.getActivity(mContext, 0, intent,
                    PendingIntent.FLAG_IMMUTABLE);
            // Use a version of this package that does not exist on the device to make this a
            // noop after the permission check.
            VersionedPackage versionedPackage = new VersionedPackage(mPackageName, 0);
            mPackageInstaller.uninstall(versionedPackage, pendingIntent.getIntentSender());
        }));

        // android.permission.RESTART_PACKAGES only guarded ActivityManager#restartPackages which
        // is no longer supported.

        mPermissionTasks
                .put(SET_WALLPAPER,
                        new PermissionTest(false, () -> mWallpaperManager.clearWallpaper()));

        mPermissionTasks.put(SET_WALLPAPER_HINTS, new PermissionTest(false, () -> {
            Rect rect = new Rect(0, 0, 1, 1);
            mWallpaperManager.setDisplayPadding(rect);
        }));

        // android.permission.SUBSCRIBED_FEEDS_READ has been removed.

        // android.permission.SUBSCRIBED_FEEDS_WRITE has been removed.

        mPermissionTasks.put(TRANSMIT_IR, new PermissionTest(false, () -> {
            try {
                if(mConsumerIrManager == null){
                    throw new BypassTestException("Can not find consumer_ir service on this device");
                }

                mLogger.logSystem("mCIR.hasIrEmitter(): " + mConsumerIrManager.hasIrEmitter());
                if (mConsumerIrManager.hasIrEmitter()) {
                    mConsumerIrManager.getCarrierFrequencies();
                } else {
                    throw new BypassTestException("this device device doesn't have ir emitter");
                }

            } catch (UnsupportedOperationException e) {
                // This Exception indicates the app has been granted the required permission to
                // invoke this API but the device does not have the IR feature.
            }
        }));

        // android.permission.UNINSTALL_SHORTCUT is no longer used.

        mPermissionTasks.put(USE_BIOMETRIC, new PermissionTest(false, () -> {
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P) {
                FingerprintManager fingerprintManager =
                        (FingerprintManager) mContext.getSystemService(
                                Context.FINGERPRINT_SERVICE);
                if (fingerprintManager == null) {
                    throw new BypassTestException(
                            "The FingerprintManager is not available on this device");
                }
                fingerprintManager.isHardwareDetected();
            } else {
                // The BiometricManager was introduced in Android 10 and is more appropriate to use
                // for this permission. Android 10 introduced the canAuthenticate method while
                // Android 11 deprecated that in favor of an overloaded version that accepts
                // an int representing Authenticators.
                BiometricManager biometricManager = null;

                biometricManager = (BiometricManager) mContext.getSystemService(
                        Context.BIOMETRIC_SERVICE);

                if (mDeviceApiLevel == Build.VERSION_CODES.Q) {
                    biometricManager.canAuthenticate();
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R){
                    biometricManager.canAuthenticate(
                            BiometricManager.Authenticators.BIOMETRIC_STRONG);
                }

            }
        }));

        // android.permission.USE_CREDENTIALS has been removed.

        // android.permission.USE_FINGERPRINT has been removed (as of SDK level 28)


        mPermissionTasks.put(VIBRATE, new PermissionTest(false, () -> mVibrator
                .vibrate(VibrationEffect.createOneShot(100, VibrationEffect.DEFAULT_AMPLITUDE))));

        mPermissionTasks.put(WAKE_LOCK, new PermissionTest(false, () -> {
            PowerManager.WakeLock wakeLock = mPowerManager.newWakeLock(
                    PowerManager.PARTIAL_WAKE_LOCK,
                    InstallPermissionTester.class.getSimpleName() + "::" + TAG);
            wakeLock.acquire(10*60*1000L /*10 minutes*/);
            wakeLock.release();
        }));

        // android.permission.WRITE_HISTORY_BOOKMARKS has been removed.

        // android.permission.WRITE_PROFILE has been removed.

        // android.permission.WRITE_SMS has been removed.

        // android.permission.WRITE_SOCIAL_STREAM has been removed.

        mPermissionTasks.put(WRITE_SYNC_SETTINGS,
                new PermissionTest(false, () -> ContentResolver.setMasterSyncAutomatically(true)));

        // android.permission.WRITE_USER_DICTIONARY has been removed.

        // new install permissions for Q
        mPermissionTasks.put(REQUEST_PASSWORD_COMPLEXITY,
                new PermissionTest(false, Build.VERSION_CODES.Q,
                        () -> {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                mDevicePolicyManager.getPasswordComplexity();
                            }
                }));

        mPermissionTasks.put(USE_FULL_SCREEN_INTENT,
                new PermissionTest(false, Build.VERSION_CODES.Q,Build.VERSION_CODES.S, () -> {

                    Intent notificationIntent = new Intent(mContext, MainActivity.class);
                    PendingIntent pendingIntent = PendingIntent.getActivity(mContext, 0,
                            notificationIntent, PendingIntent.FLAG_IMMUTABLE);

                    Resources resources = mContext.getResources();
                    CharSequence channelName = resources.getString(R.string.tester_channel_name);
                    NotificationChannel channel = new NotificationChannel(TAG, channelName,
                            NotificationManager.IMPORTANCE_DEFAULT);
                    NotificationManager notificationManager = mContext.getSystemService(
                            NotificationManager.class);
                    notificationManager.createNotificationChannel(channel);

                    Notification notification =
                            new Notification.Builder(mContext, TAG)
                                    .setContentTitle(resources.getText(
                                            R.string.full_screen_intent_notification_title))
                                    .setContentText(resources.getText(
                                            R.string.full_screen_intent_notification_message))
                                    .setSmallIcon(R.drawable.ic_launcher_foreground)
                                    .setContentIntent(pendingIntent)
                                    .setFullScreenIntent(pendingIntent, false)
                                    .build();
                    notificationManager.notify(0, notification);
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        mLogger.logError("Caught an InterruptedException: " + e);
                    }
                    StatusBarNotification[] notifications =
                            notificationManager.getActiveNotifications();

                    if (notifications.length == 0) {
                        throw new SecurityException(
                                "fullScreenIntent not displayed as an active notification");
                    }
                    for (StatusBarNotification statusBarNotification : notifications) {
                        if (statusBarNotification.getNotification().fullScreenIntent == null) {
                            throw new SecurityException(
                                    "fullScreenIntent field cleared after launching notification");
                        }
                    }
                }));

        // new install permissions for R
        mPermissionTasks.put(NFC_PREFERRED_PAYMENT_INFO,
                new PermissionTest(false, Build.VERSION_CODES.R, () -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(mContext);
                        if (adapter == null) {
                            throw new BypassTestException(
                                    "An NFC adapter is not available to run this test");
                        }
                        CardEmulation cardEmulation = CardEmulation.getInstance(adapter);
                        cardEmulation.getDescriptionForPreferredPaymentService();
                    }
                }));


        mPermissionTasks.put(QUERY_ALL_PACKAGES,
                new PermissionTest(false, Build.VERSION_CODES.R, () -> {
                    try {
                        //If the app is running with platform signature the test will be skipped.
                        // 1. We can test this permission with normal variant.
                        // 2. There is a test case which fails it it is declared.
                        if(mPlatformSignatureMatch){
                            final String msg = "The test for QUERY_ALL_PACKAGES permission is bypassed " +
                                    "when the app is signing with a platform signature." +
                                    "(see details in the process document)";
                            mLogger.logSystem(msg);
                            throw new BypassTestException(msg);
                        }
                        // The companion package should be installed to act as a queryable package
                        // for this test; without a <queries> tag in the AndroidManifest and without
                        // this permission granted a query for the companion package should result
                        // in a NameNotFoundException.
                        PackageInfo packageInfo = mPackageManager.getPackageInfo(
                                Constants.COMPANION_PACKAGE, 0);
                    } catch (PackageManager.NameNotFoundException e) {
                        throw new SecurityException(e);
                    }
                }));

        // The following are the new install permissions for Android 12.
        mPermissionTasks.put(HIDE_OVERLAY_WINDOWS,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    // The API guarded by this permission must be run on the UI thread if the
                    // permission is granted, but if the permission is not granted the resulting
                    // SecurityException will crash the app. If the permission is not granted then
                    // run the API here where the SecurityException can be handled, and if the
                    // permission is granted then run it on the UI thread since an exception should
                    // not be thrown in that case.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        if (mContext.checkSelfPermission(HIDE_OVERLAY_WINDOWS) != PackageManager.PERMISSION_GRANTED) {
                            mActivity.getWindow().setHideOverlayWindows(true);
                        } else {
                            mActivity.runOnUiThread(
                                    () -> mActivity.getWindow().setHideOverlayWindows(true));

                        }
                    }
                }));

        // HIGH_SAMPLING_RATE_SENSORS will only throw a SecurityException if the package is
        // debuggable.

        mPermissionTasks.put(REQUEST_COMPANION_PROFILE_WATCH,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    //commonize the tester routine with exposing the builder of AssociationRequest object
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                        CompletableFuture<AssociationRequest> associationRequest =
                                new CompletableFuture<AssociationRequest>().completeAsync(() ->
                                        new AssociationRequest.Builder().setDeviceProfile(
                                                AssociationRequest.DEVICE_PROFILE_WATCH).build());
                        TesterUtils.tryBluetoothAssociationRequest
                                (mPackageManager, activity, associationRequest);
                    }
            }));

        mPermissionTasks.put(REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE,
                new PermissionTest(false, Build.VERSION_CODES.S, () -> {
                    // Note: this could potentially be a fragile test since there is no companion
                    // device associated with this app so when the permission is granted the call
                    // results in a RuntimeException in the binder call, but during testing this
                    // Exception was not thrown back to this test. If in a future release this test
                    // fails because the Exception crosses the binder call then this test will need
                    // to differentiate between a SecurityException and the RuntimeException.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        CompanionDeviceManager companionDeviceManager = mActivity.getSystemService(
                                CompanionDeviceManager.class);
                        companionDeviceManager.startObservingDevicePresence("11:22:33:44:55:66");
                    }
                }));

        // UPDATE_PACKAGES_WITHOUT_USER_ACTION requires a package that can be used for the update
        // and only determines whether the user will be prompted to allow the update.

        mPermissionTasks.put(SCHEDULE_EXACT_ALARM,
                new PermissionTest(false, Build.VERSION_CODES.S,Build.VERSION_CODES.TIRAMISU, () -> {


                    Intent intent = new Intent(mContext, MainActivity.class);
                    PendingIntent pendingIntent = PendingIntent.getActivity(mContext, 0, intent,
                            PendingIntent.FLAG_IMMUTABLE);
                    AlarmManager alarmManager = mContext.getSystemService(AlarmManager.class);
                    alarmManager.setExact(AlarmManager.RTC, System.currentTimeMillis() + 60 * 1000,
                            pendingIntent);
                    alarmManager.cancel(pendingIntent);
                }));

        //New Install Permissions for T

        //Allows read only access to phone state with a non dangerous permission,
        //including the information like cellular network type, software version.
        mPermissionTasks.put(READ_BASIC_PHONE_STATE,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU, () -> {
                    //Get Cellular network type
                    TelephonyManager tm = mContext.getSystemService(TelephonyManager.class);
                    tm.getDataNetworkType();
                }));

        mPermissionTasks.put(USE_EXACT_ALARM,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU, () -> {
                    // USE_EXACT_ALARM is an install permission, and that is only
                    // differenceies against the SCHEDULE_EXACT_ALRAM permission.
                    Intent intent = new Intent(mContext, MainActivity.class);
                    PendingIntent pendingIntent = PendingIntent.getActivity(mContext, 0, intent,
                            PendingIntent.FLAG_IMMUTABLE);
                    AlarmManager alarmManager = mContext.getSystemService(AlarmManager.class);
                    alarmManager.setExact(AlarmManager.RTC, System.currentTimeMillis() + 60 * 1000,
                            pendingIntent);
                    alarmManager.cancel(pendingIntent);
                }));

        mPermissionTasks.put(READ_NEARBY_STREAMING_POLICY,
                new PermissionTest(false, Build.VERSION_CODES.TIRAMISU, () -> {
                        //This permission's category has been moved to install permission after Android T
                        if (!mPackageManager.hasSystemFeature(PackageManager.FEATURE_DEVICE_ADMIN)) {
                            throw new BypassTestException("This permission requires feature "
                                    + PackageManager.FEATURE_DEVICE_ADMIN);
                        }
                        mTransacts.invokeTransact(Transacts.DEVICE_POLICY_SERVICE,
                                Transacts.DEVICE_POLICY_DESCRIPTOR,
                                Transacts.getNearbyNotificationStreamingPolicy, 0);
                    }
                ));

        //Android 14
        mPermissionTasks.put(REQUEST_COMPANION_PROFILE_GLASSES,  new PermissionTest(false,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            //commonize the tester routine with exposing the builder of AssociationRequest object
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                CompletableFuture<AssociationRequest> associationRequest =
                    new CompletableFuture<AssociationRequest>().completeAsync(() -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                            return new AssociationRequest.Builder()
                                    .setDeviceProfile(AssociationRequest.DEVICE_PROFILE_GLASSES).build();
                        } else {
                            return null;
                        }
                    });
                TesterUtils.tryBluetoothAssociationRequest
                        (mPackageManager,activity, associationRequest);
            }
        }));

        mPermissionTasks.put(RUN_USER_INITIATED_JOBS,  new PermissionTest(false,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                NetworkRequest nreq = new NetworkRequest.Builder()
                        .addCapability(NET_CAPABILITY_INTERNET)
                        .addCapability(NET_CAPABILITY_VALIDATED).build();
                ComponentName componentName =
                        new ComponentName(mContext, TestJobService.class);
                JobInfo jobInfo = new JobInfo.Builder(1001,componentName)
                        .setUserInitiated(true)
                        .setRequiredNetwork(nreq)
                        .setEstimatedNetworkBytes(1024 * 1024,1024 * 1024)
                        .build();
                JobScheduler jobScheduler = (JobScheduler)
                        mContext.getSystemService(Context.JOB_SCHEDULER_SERVICE);
                jobScheduler.schedule(jobInfo);

            }
        }));

        mPermissionTasks.put(DETECT_SCREEN_CAPTURE,  new PermissionTest(false,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            if (android.os.Build.VERSION.SDK_INT >= 34) {
                final Activity.ScreenCaptureCallback cb
                        = new Activity.ScreenCaptureCallback() {
                            @Override
                            public void onScreenCaptured() {
                                // Add logic to take action in your app.
                                mLogger.logDebug("screen captured");
                            }
                        };
                try {
                    mActivity.registerScreenCaptureCallback(mExecutorService, cb);
                    Screenshot.capture();
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                } catch (Throwable ex){
                    throw ex;
                } finally {
                    mActivity.unregisterScreenCaptureCallback(cb);//close it anyway
                }
            }
        }));


        mPermissionTasks.put(CREDENTIAL_MANAGER_SET_ORIGIN,  new PermissionTest(false,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            CredentialManager credentialManager = CredentialManager.create(mContext);
            //credentialManager.getCredential()
            List<CredentialOption> options = new ArrayList<>();
            options.add(new GetPublicKeyCredentialOption("{}"));
            GetCredentialRequest credentialRequest = new GetCredentialRequest.Builder()
                    .setCredentialOptions(options)
                    //Check : use setOrigin method
                    .setOrigin("hoge")
                    .build();

            credentialManager.getCredentialAsync(mContext,
                    credentialRequest,
                    null,
                    new LocalDirectExecutor(),
                    new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                        @Override
                        public void onResult(GetCredentialResponse getCredentialResponse) {
                        }
                        @Override
                        public void onError(@NonNull GetCredentialException e) {
                        }
                    }
            );
        }));

        mPermissionTasks.put(CREDENTIAL_MANAGER_SET_ALLOWED_PROVIDERS,  new PermissionTest(false,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            CredentialManager credentialManager = CredentialManager.create(mContext);
            //credentialManager.getCredential()
            List<CredentialOption> options = new ArrayList<>();
            Set<ComponentName> componentNames = new HashSet<>();
            componentNames.add(new ComponentName("package","cls"));
            //Check : add allowed provider to the option.
            options.add(new GetPublicKeyCredentialOption("{}",null, componentNames));
            GetCredentialRequest credentialRequest = new GetCredentialRequest.Builder()
                    .setCredentialOptions(options)
                    .build();
            credentialManager.getCredentialAsync(mContext,
                    credentialRequest,
                    null,
                    new LocalDirectExecutor(),
                    new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                        @Override
                        public void onResult(GetCredentialResponse getCredentialResponse) {
                        }
                        @Override
                        public void onError(@NonNull GetCredentialException e) {
                        }
                    }
            );
        }));

        //"android.permission.DETECT_SCREEN_RECORDING",
        //"android.permission.ACCESS_HIDDEN_PROFILES",
        //"android.permission.FOREGROUND_SERVICE_MEDIA_PROCESSING"

        //New install permissions for Android 15(VIC)
        mPermissionTasks.put(DETECT_SCREEN_RECORDING,
                new PermissionTest(false, Build.VERSION_CODES.UPSIDE_DOWN_CAKE, () -> {
                    //IScreenCallback Constructor might be hidden
                    //If the error message is shown please execute below command from adb
                    //adb shell settings put global hidden_api_policy  1
                    IScreenRecordingCallback callback = new IScreenRecordingCallback() {
                        @Override
                        public IBinder asBinder() {
                            return null;
                        }
                        @Override
                        public void onScreenRecordingStateChanged(boolean visibleInScreenRecording) throws RemoteException {
                            System.out.println("visibleInScreenRecording:"+visibleInScreenRecording);
                        }
                    };
                    //OK
                    mTransacts.invokeTransact(Transacts.WINDOW_SERVICE,
                            Transacts.WINDOW_DESCRIPTOR,
                            Transacts.registerScreenRecordingCallback, callback);
                }));

        mPermissionTasks.put("android.permission.ACCESS_HIDDEN_PROFILES",
                new PermissionTest(false, Build.VERSION_CODES.UPSIDE_DOWN_CAKE, () -> {
                    if(Build.VERSION.SDK_INT>=35){
                        throw new BypassTestException(
                                "We can't access space setting intent by normal signature as of sdk35. " +
                                "So we exec same test on siganature permission tester. Ignore this result.");
                    }

                    LauncherApps launcherApps = (LauncherApps)
                            mContext.getSystemService(Context.LAUNCHER_APPS_SERVICE);
                    //If the caller cannot access hidden profiles the method returns null
                    // see also. areHiddenApisChecksEnabled() in LauncherAppService
                    Object intent = ReflectionUtils.invokeReflectionCall
                            (launcherApps.getClass(),
                                    "getPrivateSpaceSettingsIntent",
                                    launcherApps,new Class[]{});
                    String a = ReflectionUtils.checkDeclaredMethod(launcherApps,"get").toString();
                    if(intent == null){

                      throw new SecurityException("Caller cannot access hidden profiles");
                    }
                }));



        //Infeasible to test - can't raise security error as of now.
        //CREDENTIAL_MANAGER_QUERY_CANDIDATE_CREDENTIALS,

        //Infeasible to test can't raise security error as of now.
        //ENFORCE_UPDATE_OWNERSHIP
        /*
        mPermissionTasks.put(ENFORCE_UPDATE_OWNERSHIP,  new PermissionTest(false,
                Build.VERSION_CODES.UPSIDE_DOWN_CAKE,() -> {
            PackageInstaller.Session session = null;
            try {
                PackageInstaller packageInstaller = mPackageInstaller;
                PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                        PackageInstaller.SessionParams.MODE_FULL_INSTALL);
                params.setInstallLocation(PackageInfo.INSTALL_LOCATION_INTERNAL_ONLY);
                params.setRequestUpdateOwnership(true);//Checking parasms
                int sessionId = packageInstaller.createSession(params);
                PackageInstaller.SessionCallback sessionCallback = new
                        PackageInstaller.SessionCallback() {
                            @Override
                            public void onCreated(int i) {
                              ;
                            }

                            @Override
                            public void onBadgingChanged(int i) {

                            }

                            @Override
                            public void onActiveChanged(int i, boolean b) {
                            }

                            @Override
                            public void onProgressChanged(int i, float v) {
                            }
                            @Override
                            public void onFinished(int i, boolean b) {
                            }
                        };

                packageInstaller.registerSessionCallback(sessionCallback);
                PackageInstaller.Session s = packageInstaller.openSession(sessionId);
            } catch (IOException ex) {
                throw new SecurityException(ex);
            }
        });
         */

    }


    class LocalDirectExecutor implements Executor {
        public void execute(Runnable r) {
            r.run();
        }
    }


    /**
     * Runs all of the permission tests for install permissions and returns a {@code boolean}
     * indicating whether all of the tests completed successfully.
     */
    @Override
    public boolean runPermissionTests() {
        boolean allTestsPassed = true;
        List<String> permissions = mConfiguration.getInstallPermissions().orElse(
                new ArrayList<>(mPermissionTasks.keySet()));
        for (String permission : permissions) {
            if (!runPermissionTest(permission, mPermissionTasks.get(permission))) {
                allTestsPassed = false;
            }
        }
        if (allTestsPassed) {
            mLogger.logInfo(
                    "*** PASSED - all install permission tests completed successfully");
        } else {
            mLogger.logInfo("!!! FAILED - one or more install permission tests failed");
        }
        return allTestsPassed;
    }
    public void runPermissionTestsByThreads(Consumer<Result> callback){
        Result.testerName = this.getClass().getSimpleName();

        List<String> permissions = mConfiguration.getInstallPermissions().orElse(
                new ArrayList<>(mPermissionTasks.keySet()));

        int no=0;
        AtomicInteger cnt = new AtomicInteger(0);
        AtomicInteger err = new AtomicInteger(0);

        final int total = permissions.size();
           for (String permission : permissions) {Thread thread = new Thread(() -> {
               String tester = this.getClass().getSimpleName();
               if (runPermissionTest(permission, mPermissionTasks.get(permission), true)) {
                   callback.accept(new Result(true, permission, aiIncl(cnt), total,err.get(),tester));
               } else {
                   callback.accept(new Result(false, permission, aiIncl(cnt), total,aiIncl(err),tester));
               }
           });

            // If the permission has a corresponding task then run it.
            // mLogger.logDebug("Starting test for signature permission: "+String.format(Locale.US,
            //"%d/%d ",no,numperms) + permission);

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

    private void tryBindingForegroundService(Intent serviceIntent){
        FgServiceConnection serviceConnection = new FgServiceConnection();
        mContext.bindService(serviceIntent,
                Context.BIND_AUTO_CREATE, mExecutorService,serviceConnection);
        synchronized (lock) {
            try {
                int i=0;

                while (!serviceConnection.mConnected.get()) {
                    try {
                        //wait almost 1 sec along increasing waiting time
                        lock.wait(10+(i*i));
                        if(i++>=40){
                            throw new InterruptedException("Connection Timed Out");
                        }
                    } catch (InterruptedException e) {
                        throw new UnexpectedPermissionTestFailureException(e.getMessage());
                    }
                }
                //mLogger.logInfo("Connected To Service in the Tester app="+serviceConnection.mComponentName+
                //        ","+serviceConnection.binderSuccess.get());
                if(!serviceConnection.binderSuccess.get()){
                    throw new SecurityException("Test for "+serviceConnection.mComponentName+" has been failed.");
                }
                //mLogger.logSystem("binder success"+serviceConnection.mComponentName);
            } catch (Exception ex){
                //mLogger.logSystem("binder !exception"+serviceConnection.mComponentName);
                throw new UnexpectedPermissionTestFailureException(ex);
            } finally {
                mContext.unbindService(serviceConnection);
            }
        }
    }
    final Object lock = new Object();
    private class FgServiceConnection implements android.content.ServiceConnection {
        public final AtomicBoolean binderSuccess = new AtomicBoolean();
        private final AtomicBoolean mConnected = new AtomicBoolean(false);
        public String mComponentName = "";
        public void onServiceConnected(ComponentName name, IBinder binder) {
            synchronized (lock) {
                mConnected.set(true);
                binderSuccess.set(false);
                mComponentName = name.getShortClassName();
                TestBindService service = TestBindService.Stub.asInterface(binder);
                try {
                    service.testMethod();
                    binderSuccess.set(true);
                } catch (RemoteException e) {
                    binderSuccess.set(false);
                    mLogger.logError(name+" failure."+e.getMessage(),e);
                }
                lock.notify();
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName componentName) {
            //Unimplemented
        }
    }
}
