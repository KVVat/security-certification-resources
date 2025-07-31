/*
 * Copyright (C) 2024 The Android Open Source Project
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
package android.security.authenticationpolicy;

import android.os.Parcel;
import android.os.Parcelable;

import java.util.Objects;


/**
 * Parameters related to a request to enable secure lock on the device.
 *
 * @hide
 */
public final class EnableSecureLockDeviceParams implements Parcelable {

    /**
     * Client message associated with the request to enable secure lock on the device. This message
     * will be shown on the device when secure lock mode is enabled.
     *
     * Since this text is shown in a restricted lockscreen state, typeface properties such as color,
     * font weight, or other formatting may not be honored.
     */
    private final CharSequence mMessage;

    /**
     * Creates EnableSecureLockDeviceParams with the given params.
     *
     * @param message Allows clients to pass in a message with information about the request to
     *                enable secure lock on the device. This message will be shown to the user when
     *                secure lock mode is enabled. If an empty CharSequence is provided, it will
     *                default to a system-defined CharSequence (e.g. "Device is securely locked
     *                remotely.")
     *
     *                Since this text is shown in a restricted lockscreen state, typeface properties
     *                such as color, font weight, or other formatting may not be honored.
     */
    public EnableSecureLockDeviceParams(CharSequence message) {
        mMessage = message;
    }

    private EnableSecureLockDeviceParams(Parcel in) {
        mMessage = Objects.requireNonNull(in.readString());
    }

    public static final Creator<EnableSecureLockDeviceParams> CREATOR =
            new Creator<EnableSecureLockDeviceParams>() {
                @Override
                public EnableSecureLockDeviceParams createFromParcel(Parcel in) {
                    return new EnableSecureLockDeviceParams(in);
                }

                @Override
                public EnableSecureLockDeviceParams[] newArray(int size) {
                    return new EnableSecureLockDeviceParams[size];
                }
            };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(mMessage.toString());
    }
}