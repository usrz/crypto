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
package org.usrz.libs.crypto.pem;

import static java.util.logging.Level.WARNING;
import static org.usrz.libs.crypto.codecs.Base64Codec.BASE_64;
import static org.usrz.libs.crypto.codecs.CharsetCodec.ASCII;
import static org.usrz.libs.crypto.codecs.HexCodec.HEX;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.usrz.libs.crypto.pem.PEMEntry.Encryption;
import org.usrz.libs.crypto.pem.PEMEntry.Type;

/**
 * A reader for PEM-formatted files.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class PEMReader {

    private static final Logger LOGGER = Logger.getLogger(PEMKeyStoreSpi.class.getName());

    private static final Pattern BEGIN_CERTIFICATE = Pattern.compile("^--+\\s*BEGIN\\s+CERTIFICATE\\s*--+$");
    private static final Pattern END_CERTIFICATE =   Pattern.compile("^--+\\s*END\\s*+CERTIFICATE\\s*--+$");

    private static final Pattern BEGIN_PRIVATE_KEY = Pattern.compile("^--+\\s*BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY\\s*--+$");
    private static final Pattern END_PRIVATE_KEY =   Pattern.compile("^--+\\s*END\\s+(RSA\\s+)?PRIVATE\\s+KEY\\s*--+$");

    private static final Pattern BEGIN_PUBLIC_KEY = Pattern.compile("^--+\\s*BEGIN\\s+(RSA\\s+)?PUBLIC\\s+KEY\\s*--+$");
    private static final Pattern END_PUBLIC_KEY =   Pattern.compile("^--+\\s*END\\s+(RSA\\s+)?PUBLIC\\s+KEY\\s*--+$");

    private static final Pattern HEADER = Pattern.compile("^[\\w-_]+:\\s+.*");
    private static final Pattern HEADER_ENCRYPTED = Pattern.compile("^Proc-Type:\\s+4\\s*,\\s*ENCRYPTED\\s*$");
    private static final Pattern HEADER_DEK_INFO = Pattern.compile("^DEK-Info:\\s+([^,]+)\\s*,\\s*(.+)\\s*$");

    private enum State { HEADER_OR_DATA, HEADER, DATA }
    private final BufferedReader reader;
    private final URL url;

    /**
     * Create a {@link PEMReader} loading from a {@link URL}.
     */
    public PEMReader(URL url)
    throws IOException {
        this(url, new InputStreamReader(url.openStream(), ASCII));
    }

    /**
     * Create a {@link PEMReader} loading from an {@link InputStream}.
     */
    public PEMReader(InputStream input) {
        this(null, new InputStreamReader(input, ASCII));
    }

    /**
     * Create a {@link PEMReader} loading from an {@link InputStream}.
     */
    public PEMReader(InputStream input, String charsetName) {
        this(null, new InputStreamReader(input, charsetName == null ? ASCII : Charset.forName(charsetName)));
    }

    /**
     * Create a {@link PEMReader} loading from an {@link InputStream}.
     */
    public PEMReader(InputStream input, Charset charset) {
        this(null, new InputStreamReader(input, charset == null ? ASCII : charset));
    }

    /**
     * Create a {@link PEMReader} loading from an {@link Reader}.
     */
    public PEMReader(Reader reader) {
        this(null, reader);
    }

    /* Our internal constructor */
    private PEMReader(URL url, Reader reader) {
        this.url = url;
        this.reader = reader instanceof BufferedReader ?
                              (BufferedReader) reader :
                              new BufferedReader(reader);
    }

    /**
     * Reat a {@linkplain List list} of {@linkplain PEMEntry entries} from the
     * input specified at construction.
     */
    public List<PEMEntry<?>> read()
    throws IOException, PEMException {
        final List<PEMEntry<?>> entries = new ArrayList<>();

        try {
            Entry entry = null;
            String line = reader.readLine();
            while (line != null) {
                /* Line is not null, trim it */
                line = line.trim();

                /* No entry? We're outside of a block */
                if (entry == null) {

                    /* New certificate? */
                    if (BEGIN_CERTIFICATE.matcher(line).matches()) {
                        entry = new Entry(Type.X509_CERTIFICATE);

                    /* New public key? */
                    } else if (BEGIN_PUBLIC_KEY.matcher(line).matches()) {
                        entry = new Entry(Type.RSA_PUBLIC_KEY);

                    /* New private key? */
                    } else if (BEGIN_PRIVATE_KEY.matcher(line).matches()) {
                        entry = new Entry(Type.RSA_PRIVATE_KEY);
                    }

                    /* Anything else is garbage/comments/... ignore it, next! */
                    line = reader.readLine();
                    continue;

                }

                /* We have an entry, switch on state */
                switch (entry.state) {

                    case HEADER_OR_DATA:

                        /* Empty line can be ignored */
                        if (line.length() == 0) break;

                        /* Is this a header or data block? */
                        if (HEADER.matcher(line).matches()) {
                            entry.state = State.HEADER;
                        } else {
                            entry.state = State.DATA;
                        }

                        /* Reprocess the *CURRENT* line in HEADER or DATA state */
                        continue;

                    case HEADER:

                        /* Empty line means the end of a header block */
                        if (line.length() == 0) {
                            entry.state = State.DATA;
                            break;
                        }

                        /* Is this a "Encrypted" flag header? */
                        if (HEADER_ENCRYPTED.matcher(line).matches()) {
                            entry.encrypted = true;
                            break;
                        }

                        /* Is this our decryption info header? */
                        final Matcher matcher = HEADER_DEK_INFO.matcher(line);
                        if (matcher.matches()) {
                            entry.encryption= matcher.group(1);
                            entry.salt = matcher.group(2);
                            break;
                        }

                        /* Unrecognized header, bail out */
                        throw new PEMException(url, "Unrecognized header: " + line);

                    case DATA:

                        /* Check if this is the end of a certificate */
                        if (END_CERTIFICATE.matcher(line).matches()) {
                            entries.add(entry.end(Type.X509_CERTIFICATE));
                            entry = null;
                            break;
                        }

                        /* Check if this is the end of a public key */
                        if (END_PUBLIC_KEY.matcher(line).matches()) {
                            entries.add(entry.end(Type.RSA_PUBLIC_KEY));
                            entry = null;
                            break;
                        }

                        /* Check if this is the end of a private key */
                        if (END_PRIVATE_KEY.matcher(line).matches()) {
                            entries.add(entry.end(Type.RSA_PRIVATE_KEY));
                            entry = null;
                            break;
                        }

                        /* Anything else MUST be Base64 data */
                        entry.data.append(line);
                        break;
                }

                /* Done with our "switch" statement above, read next line */
                line = reader.readLine();

            }

            /* We sure we read the whole thing? */
            if (entry != null) throw new PEMException(url, "PEM file truncated reading element of type " + entry.type);

            /* Check we actually found some real data */
            if (entries.size() == 0) throw new PEMException(url, "No data found in PEM file");

        } finally {
            try {
                reader.close();
            } catch (IOException exception) {
                LOGGER.log(WARNING, "Exception closing reader", exception);
            }
        }

        /* Return what we got */
        return entries;
    }

    /* ====================================================================== */

    private class Entry {

        private final StringBuilder data;
        private final Type type;

        private State state;
        private String salt;
        private String encryption;
        private boolean encrypted;

        private Entry(Type type) {
            state = State.HEADER_OR_DATA;
            data = new StringBuilder();
            this.type = type;
        }

        private PEMEntry<?> end(Type type)
        throws PEMException {
            if (type != this.type)
                throw new PEMException(url, "Mismatched begin/end blocks, looking for " + this.type + " but got " + type);

            if (!encrypted) {
                /* Not encrypted, check we don't have a spurious encryption entry */
                if (encryption != null) throw new PEMException(url, "Encryption algorithm specified for non-encrypted entry");
                if (salt != null) throw new PEMException(url, "Salt specified for non-encrypted entry");

            } else {
                /* Encrypted, check that we have the proper values */
                if (encryption == null) throw new PEMException(url, "No encryption algorightm found for encrypted entry");
                if (salt == null) throw new PEMException(url, "No salt found for encrypted entry");
            }

            /* Figure out the encryption algorithm */
            final Encryption realEncryption;
            try {
                realEncryption = encryption == null ? null : Encryption.normalizedValueOf(encryption.trim());
            } catch (Exception exception) {
                throw new PEMException(url, "Invalid/unsupported encryption " + encryption);
            }

            /* Figure out the salt */
            final byte[] realSalt;
            try {
                realSalt = salt == null ? null : HEX.decode(salt);
            } catch (Exception exception) {
                throw new PEMException(url, "Unable to decode salt " + salt);
            }

            /* Figure out the data */
            final byte[] realData;
            try {
                realData = BASE_64.decode(data.toString());
            } catch (Exception exception) {
                throw new PEMException(url, "Unable to decode salt " + salt);
            }

            /* Last check */
            if (realData.length == 0)
                throw new PEMException(url, "Empty data block in PEM");
            if ((realSalt != null) && (realSalt.length == 0))
                throw new PEMException(url, "Empty salt for decryption");

            /* Return the final entry */
            switch (type) {
                case RSA_PRIVATE_KEY:  return new PEMRSAPrivateKeyEntry(realData, realSalt, realEncryption);
                case RSA_PUBLIC_KEY:   return new PEMRSAPublicKeyEntry(realData, realSalt, realEncryption);
                case X509_CERTIFICATE: return new PEMX509CertificateEntry(realData, realSalt, realEncryption);
            }

            /* Should really never happen */
            throw new PEMException(url, "Unsupported block type " + type);
        }
    }
}
