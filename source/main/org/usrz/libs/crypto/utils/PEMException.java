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
package org.usrz.libs.crypto.utils;

import java.net.URL;
import java.security.GeneralSecurityException;

/**
 * An exception thrown whenever there was a problem decoding a PEM file.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class PEMException extends GeneralSecurityException {

    public PEMException(String message, URL url) {
        this(message, url, null);
    }

    public PEMException(String message, URL url, Throwable cause) {
        super(new StringBuilder()
                        .append(message == null? "Unknown error": message)
                        .append(url == null? "": " parsing " + url.toString())
                        .toString(),
              cause);
    }

}
