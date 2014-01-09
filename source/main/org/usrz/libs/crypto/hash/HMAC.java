/* ========================================================================== *
 * Copyright 2014 USRZ.com and Pier Paolo Fumagalli                           *
 * -------------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *  http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 * ========================================================================== */
package org.usrz.libs.crypto.hash;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

public class HMAC extends AbstractFunction<HMAC> {

    private final Mac mac;

    protected HMAC(Hash hash, Mac mac) {
        super(hash);
        assert (mac != null): "Null Mac";
        this.mac = mac;
    }

    public final Mac getMac() {
        return mac;
    }

    @Override
    public final HMAC reset() {
        mac.reset();
        return this;
    }

    @Override
    public HMAC update(byte[] input, int offset, int length) {
        mac.update(input, offset, length);
        return this;
    }

    @Override
    public void finish(byte[] output, int offset) {
        try {
            mac.doFinal(output, offset);
        } catch (ShortBufferException exception) {
            throw new IllegalArgumentException("Buffer too short", exception);
        }
    }

}
