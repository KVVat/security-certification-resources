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
package android.security;

import android.security.AppUriAuthenticationPolicy;
import android.net.Uri;
import java.util.List;

interface IKeyChainService {
    // APIs used by KeyChain
    String requestPrivateKey(String alias);
    byte[] getCertificate(String alias);
    byte[] getCaCertificates(String alias);
    boolean isUserSelectable(String alias);
    void setUserSelectable(String alias, boolean isUserSelectable);

    int generateKeyPair(in String algorithm, in String /*ParcelableKeyGenParameterSpec*/ spec);
    boolean setKeyPairCertificate(String alias, in byte[] userCert, in byte[] certChain);

    // APIs used by CertInstaller and DevicePolicyManager
    String installCaCertificate(in byte[] caCertificate);

    // APIs used by DevicePolicyManager
    boolean installKeyPair(
        in byte[] privateKey, in byte[] userCert, in byte[] certChain, String alias, int uid);
    boolean removeKeyPair(String alias);
    boolean containsKeyPair(String alias);
    int[] getGrants(String alias);

    // APIs used by Settings
    boolean deleteCaCertificate(String alias);
    boolean reset();
    String /* StringParceledListSlice */ getUserCaAliases();
    String /* StringParceledListSlice */ getSystemCaAliases();
    boolean containsCaAlias(String alias);
    byte[] getEncodedCaCertificate(String alias, boolean includeDeletedSystem);
    List<String> getCaCertificateChainAliases(String rootAlias, boolean includeDeletedSystem);
    void setCredentialManagementApp(String packageName, in AppUriAuthenticationPolicy policy);
    boolean hasCredentialManagementApp();
    String getCredentialManagementAppPackageName();
    AppUriAuthenticationPolicy getCredentialManagementAppPolicy();
    String getPredefinedAliasForPackageAndUri(String packageName, in Uri uri);
    void removeCredentialManagementApp();
    boolean isCredentialManagementApp(String packageName);

    // APIs used by KeyChainActivity
    // setGrant may fail with value=false when ungrant operation fails in KeyStore.
    boolean setGrant(int uid, String alias, boolean value);
    boolean hasGrant(int uid, String alias);

    // API used by Wifi
    String getWifiKeyGrantAsUser(String alias);
}
