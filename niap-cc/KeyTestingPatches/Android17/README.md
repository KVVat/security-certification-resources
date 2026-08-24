# Key Testing Patches for Android 17

We changed the patches and its styles from this version, and renewed according to the updates of
the systems and the KMD (Key Management Description) document. 

We placed the patch files in the corresponding directory.
So you can install them with overwriting, and then run patch commands one by one.

Base Version : 26Q2-release

## Patch Specs

### Patch for /system/vold/

  - Reference : Table.4 Device Encryption Keys
  - File : KeyStorage.cpp
  
  1. Dump the key passed by the ‘dir’ arg.
  1. Dump appId
  1. Dump secdiscardable_hash

### Patch for /external/wpa_supplicant_8/src/utils/
   - Reference : Table 11 TSF WPA2 Keys
   - File : wpa_debug.c

It’s a patch file for the debug line of the WPA supplicant. Display WPA2 keys forcefully.

### Patch for /system/security/keystore2/

 - Reference : Table 8 - KeyStore Hierarchy Keys 
    - KeyStore Daemon Keys (KeystoreKeys not included in the KeyMint)

#### File : [src/crypto/zvec.rs]
The u8 vector with auto-zero-padding feature when unreferenced/destroyed.
For customize zvec toString to show containers.

#### File : [src/ec_crypto.rs]
- Per-UnlockedDeviceRequired-key ECDH Shared Secret (SS)
- Per-UnlockedDeviceRequired-key AES-GCM key
- Per-UnlockedDeviceRequired-key ECDH keypair (Private)

#### File : [src/super_key.rs]

Hook, extract, create and encrypt, unlock operation to check the superkeys.

1. Add fmt::Display implementation to the SuperEncryptionAlgorithm enum.
1. pub fn extract_super_key_from_key_entry() -> Extract a super key.
    1. Read key value and algorithm
    1. Read Key Parameters like salt, iv, aead_tag
1. pub fn encrypt_with_password() -> Encrypt super_key with password
    1. Encrypted Password
    1. Key, and Password and other metadatas (iv, aead_tag, super_key)
1. pub fn encrypt_with_aes_super_key() -> Encrypt super_key with aes
    1. super_key
    1. key_blob & iv
1. pub fn encrypt_with_hybrid_super_key() -> Encrypt super_key with ecdh-521 and ephem (public key)
1. pub fn create_super_key() -> Create a super_key
    1. super_key
    1. public_key (for asymmetric key)
    1. encrypted_super_key
    1. metadata iv, user_id, password etc
1. fn unlock_unlocked_device_required_keys()
1. fn lock_unlocked_device_required_keys()
    1. biometric unlock key
1. fn try_unlock_user_with_biometric()

### Patch for /frameworks/base/services/…

 - Full Path : /frameworks/base/services/core/java/com/android/server/locksettings/
 - Reference : Table 3 - Lock Screen Key Factor Keys
 
#### File : [SyntheticPasswordCrypto.java]

 - personalizedHash to dump the keys below 
 - deriveSubkey: Derive from Synthetic Password (SP) below may be called
     - PERSONALIZATION_KEY_STORE_PASSWORD
     - PERSONALIZATION_FBE_KEY
     - PERSONALIZATION_AUTHSECRET_KEY
     - PERSONALIZATION_PASSWORD_HASH
     - PERSONALIZATION_PASSWORD_METRICS
     - PERSONALIZATION_PERSONALIZATION_AUTHSECRET_ENCRYPTION_KEY
 - recreate/PERSONALIZATION_SP_SPLIT
 - transformUnderWeaverSecret/PERSONALIZATION_WEAVER_PASSWORD
 - transformUnderSecdiscardable/PERSONALIZATION_SECDISCARDABLE
 - stretchedLskfToGkPassword/PERSONALIZATION_USER_GK_AUTH
 - stretchedLskfToWeaverKey/PERSONALIZATION_WEAVER_KEY

#### File : [SyntheticPasswordManager.java]

1. deriveSubKey/V3 synthetic password
2. createLskfBasedProtector/pwdToken
3. unwrapSyntheticPasswordBlob/protectorSecret & SyntheticPassword
4. Dumpsys support for SPM state dump

#### File : [LockSettingsService.java] 
1. setCeStorageProtection() 
    - FBE KEK, It used by encrypt the CE Storage 
2. unlockCeStorage()
3. dump() / mSpManager.dump()
