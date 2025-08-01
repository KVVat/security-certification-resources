/*
 * Copyright (C) 2025 The Android Open Source Project
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
package android.health.connect.aidl;

import android.health.connect.HealthConnectException;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;

import java.io.PrintWriter;
import java.io.StringWriter;

public final class HealthConnectExceptionParcel implements Parcelable {

    public static final Creator<HealthConnectExceptionParcel> CREATOR =
            new Creator<HealthConnectExceptionParcel>() {
                @Override
                public HealthConnectExceptionParcel createFromParcel(Parcel in) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        return new HealthConnectExceptionParcel(null);
                    } else return null;
                }

                @Override
                public HealthConnectExceptionParcel[] newArray(int size) {
                    return new HealthConnectExceptionParcel[size];
                }
            };

    private final HealthConnectException mHealthConnectException;

    public HealthConnectExceptionParcel(HealthConnectException healthConnectException) {
        mHealthConnectException = healthConnectException;
    }

    public HealthConnectException getHealthConnectException() {
        return mHealthConnectException;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(mHealthConnectException.getErrorCode());
        dest.writeString(mHealthConnectException.getMessage());
    }

    @Override
    public String toString() {
        StringWriter sw = new StringWriter();
        if (mHealthConnectException != null) {
            PrintWriter pw = new PrintWriter(sw);
            mHealthConnectException.printStackTrace(pw);
        }
        return "HealthConnectExceptionParcel: " + mHealthConnectException + "\n" + sw;
    }
}
