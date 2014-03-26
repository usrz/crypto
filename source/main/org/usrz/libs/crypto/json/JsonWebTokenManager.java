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
package org.usrz.libs.crypto.json;

import static org.usrz.libs.crypto.codecs.Base64Codec.Alphabet.URL_SAFE;
import static org.usrz.libs.crypto.codecs.CharsetCodec.UTF8;

import java.io.IOException;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.StringTokenizer;

import org.usrz.libs.crypto.codecs.Base64Codec;
import org.usrz.libs.crypto.hash.Hash;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonWebTokenManager {

    private final Base64Codec codec;
    private final Hash hash;
    private final ObjectMapper mapper;
    private final String header;

    public JsonWebTokenManager(Hash hash, ObjectMapper mapper) {
        codec = new Base64Codec(URL_SAFE, false);
        this.hash = Objects.requireNonNull(hash, "Null hash");
        this.mapper = Objects.requireNonNull(mapper, "Null mapper");
        final String algorithm;
        switch (hash) {
            case SHA256: algorithm = "HS256" ; break;
            case SHA384: algorithm = "HS384" ; break;
            case SHA512: algorithm = "HS512" ; break;
            default: throw new IllegalArgumentException("Unsupported hash " + hash);
        }
        final JsonWebTokenHeader header = new JsonWebTokenHeader("JWT", algorithm);
        try {
            final String string = mapper.writeValueAsString(header);
            final String encoded = codec.encode(string.getBytes(UTF8));
            this.header = encoded + ".";
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to encode JWT header", exception);
        }
    }

    public String create(Object object, byte[] key) {
        try {
            final String payload = mapper.writeValueAsString(object);
            final String encoded = header + codec.encode(payload.getBytes(UTF8));
            final byte[] signature = hash.hmac(key).update(encoded.getBytes(UTF8)).finish();
            return encoded + "." + codec.encode(signature);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to encode token payload", exception);
        }
    }

    public <T> T parse(String token, byte[] key, Class<T> type) {
        final StringTokenizer tokenizer = new StringTokenizer(token, ".");

        /* Basic parsing of the token */
        final JsonWebTokenHeader header;
        final String payload;
        final byte[] signature;
        final byte[] signedPart;
        try {
            final String headerToken = tokenizer.nextToken();
            final String payloadToken = tokenizer.nextToken();
            final String signatureToken = tokenizer.nextToken();
            if (tokenizer.hasMoreTokens())
                throw new IllegalArgumentException("Too many components in token \"" + token + "\"");

            header = mapper.readValue(new String(codec.decode(headerToken), UTF8), JsonWebTokenHeader.class);
            payload = new String(codec.decode(payloadToken), UTF8);
            signature = codec.decode(signatureToken);
            signedPart = (headerToken + "." + payloadToken).getBytes(UTF8);
        } catch (NoSuchElementException exception) {
            throw new IllegalArgumentException("Not enough components in token \"" + token + "\"");
        } catch (IOException exception) {
            throw new IllegalArgumentException("Unable to parse header contents for token \"" + token + "\"", exception);
        }

        /* Basic parsing of the header */
        if (! "JWT".equals(header.getType()))
            throw new IllegalArgumentException("Invalid header type \"" + header.getType() + "\" for token \"" + token + "\"");

        final Hash hash;
        if ("HS256".equals(header.getAlgorithm())) {
            hash = Hash.SHA256;
        } else if ("HS384".equals(header.getAlgorithm())) {
            hash = Hash.SHA384;
        } else if ("HS512".equals(header.getAlgorithm())) {
            hash = Hash.SHA512;
        } else {
            throw new IllegalArgumentException("Invalid header algorithm \"" + header.getAlgorithm() + "\" for token \"" + token + "\"");
        }

        /* Signature validation and de-serialization */
        final byte[] verified = hash.hmac(key).update(signedPart).finish();
        if (Arrays.equals(signature, verified)) try {
            return mapper.readValue(payload, type);
        } catch (IOException exception) {
            throw new IllegalArgumentException("Unable to parse payload contents for token \"" + token + "\"");
        } else {
            throw new IllegalArgumentException("Unable to verify signature for token \"" + token + "\"");
        }
    }

    /* ====================================================================== */
}
