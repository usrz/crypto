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
package org.usrz.libs.crypto.kdf;

import static org.usrz.libs.utils.Charsets.UTF8;
import static org.usrz.libs.utils.codecs.HexCodec.HEX;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.Arrays;

import org.usrz.libs.logging.Log;

final class SCryptNativeHelper {

    private static final Log log = new Log(SCryptNativeHelper.class);

    private static final int TEST_N = 1024;
    private static final int TEST_R = 8;
    private static final int TEST_P = 16;
    private static final int TEST_DK_LEN = 64;
    private static final byte[] TEST_PASSWORD = "password".getBytes(UTF8);
    private static final byte[] TEST_SALT = "NaCl".getBytes(UTF8);
    private static final byte[] TEST_HASH = HEX.decode("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");

    private static boolean nativeSupport = false;

    /* ====================================================================== */

    private static final boolean load() {
        try {
            final String system, architecture, extension;
            switch (System.getProperty("os.name", "unknown").toLowerCase().replace(' ', '_')) {
                case "mac_os_x": system = "macos"; extension="dylib"; break;
                case "linux":    system = "linux"; extension="so";    break;
                default:
                    log.error("Unsupported OS platform \"%s\", unable to load SCrypt library", System.getProperty("os.name"));
                    return false;
            }

            switch (System.getProperty("os.arch", "unknown").toLowerCase().replace(' ', '_')) {
                case "x86_64":
                case "amd64":  architecture = "x64"; break;
                default:
                    log.error("Unsupported OS architecture \"%s\", unable to load SCrypt library", System.getProperty("os.arch"));
                    return false;
            }

            final String prefix = "libscrypt_" + system + "_" + architecture;
            final String suffix = "." + extension;
            final String library = prefix + suffix;
            final URL resource = SCryptNativeHelper.class.getResource(library);

            if (resource == null) {
                log.error("Can't find native library \"%s\", unable to load SCrypt library", library);
                return false;
            }

            final File file = File.createTempFile(prefix, suffix);
            file.setExecutable(true);
            file.deleteOnExit();

            log.debug("Copying SCrypt library from %s to %s", resource, file);

            final InputStream input = resource.openStream();
            final OutputStream output = new FileOutputStream(file);
            final byte[] buffer = new byte[4096];
            int read = -1;
            while ((read = input.read(buffer)) >= 0) {
                if (read > 0) output.write(buffer, 0, read);
            }
            output.close();
            input.close();

            log.debug("Loading SCrypt library from %s", file.getCanonicalPath());

            final Runtime runtime = Runtime.getRuntime();
            runtime.load(file.getCanonicalPath());

            log.debug("Testing SCrypt native implementation");

            byte[] result = new byte[TEST_DK_LEN];
            scrypt(TEST_PASSWORD, TEST_SALT, result, 0, TEST_DK_LEN, TEST_N, TEST_R, TEST_P);
            if (Arrays.equals(result, TEST_HASH)) {
                log.info("SCrypt native library loaded and tested");
                return true;
            } else {
                log.error("The SCrypt native library did not produce the expected results, disabling");
                return false;
            }
        } catch (Throwable throwable) {
            log.error(throwable, "An error occurrent loading the JNI SCrypt library");
            return false;
        }
    }

    static {
        nativeSupport = load();
    }
    /* ====================================================================== */

    static native void scrypt(byte[] password, byte[] salt, byte[] out, int offset, int length, int N, int r, int p);

    static boolean isAvailable() {
        return nativeSupport;
    }

    static void enable() {
        nativeSupport = true;
    }

    static void disable() {
        nativeSupport = false;
    }

}
