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
package org.usrz.libs.crypto.vault;

import org.testng.annotations.Test;
import org.usrz.libs.crypto.kdf.OpenSSLKDFSpec;
import org.usrz.libs.testing.AbstractTest;

import com.fasterxml.jackson.databind.ObjectMapper;

public class SpecBuilderTest extends AbstractTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    public void testAESCryptoSpec() throws Exception {
        final AESCryptoSpec fromJson = (AESCryptoSpec) mapper.readValue("{\"algorithm\":\"aes\",\"kdf\":{\"function\":\"openssl\"}}", CryptoSpec.class);
        final AESCryptoSpec constructed = new AESCryptoSpec(new OpenSSLKDFSpec());

        assertEquals(fromJson, constructed);
        assertEquals(constructed, fromJson);
        assertEquals(fromJson.getKDFSpec(), constructed.getKDFSpec());
        assertEquals(fromJson.getAlgorithm(), constructed.getAlgorithm());

        final String json1 = mapper.writeValueAsString(fromJson);
        final String json2 = mapper.writeValueAsString(constructed);

        assertEquals(json1, json2);

        final CryptoSpec fromJson1 = mapper.readValue(json1, CryptoSpec.class);
        final CryptoSpec fromJson2 = mapper.readValue(json2, CryptoSpec.class);

        assertEquals(fromJson1, constructed);
        assertEquals(fromJson2, constructed);

        log.debug("AES Crypto Spec -> %s", json1);
    }

    @Test
    public void testRSACryptoSpec() throws Exception {
        final RSACryptoSpec fromJson = (RSACryptoSpec) mapper.readValue("{\"algorithm\":\"rsa\"}", CryptoSpec.class);
        final RSACryptoSpec constructed = new RSACryptoSpec();

        assertEquals(fromJson, constructed);
        assertEquals(constructed, fromJson);
        assertEquals(fromJson.getAlgorithm(), constructed.getAlgorithm());

        final String json1 = mapper.writeValueAsString(fromJson);
        final String json2 = mapper.writeValueAsString(constructed);

        assertEquals(json1, json2);

        final CryptoSpec fromJson1 = mapper.readValue(json1, CryptoSpec.class);
        final CryptoSpec fromJson2 = mapper.readValue(json2, CryptoSpec.class);

        assertEquals(fromJson1, constructed);
        assertEquals(fromJson2, constructed);

        log.debug("RSA Crypto Spec -> %s", json1);
    }

    @Test
    public void testAESVaultSpec() throws Exception {
        final AESVaultSpec fromJson = (AESVaultSpec) mapper.readValue("{\"algorithm\":\"aes\",\"kdf\":{\"function\":\"openssl\"},\"codec\":\"base64\"}", VaultSpec.class);
        final AESVaultSpec constructed = new AESVaultSpec(new OpenSSLKDFSpec(), "base64");

        assertEquals(fromJson, constructed);
        assertEquals(constructed, fromJson);
        assertEquals(fromJson.getKDFSpec(), constructed.getKDFSpec());
        assertEquals(fromJson.getAlgorithm(), constructed.getAlgorithm());

        final String json1 = mapper.writeValueAsString(fromJson);
        final String json2 = mapper.writeValueAsString(constructed);

        assertEquals(json1, json2);

        final VaultSpec fromJson1 = mapper.readValue(json1, VaultSpec.class);
        final VaultSpec fromJson2 = mapper.readValue(json2, VaultSpec.class);

        assertEquals(fromJson1, constructed);
        assertEquals(fromJson2, constructed);

        log.debug("AES Vault Spec -> %s", json1);
    }

    @Test
    public void testRSAVaultSpec() throws Exception {
        final RSAVaultSpec fromJson = (RSAVaultSpec) mapper.readValue("{\"algorithm\":\"rsa\",\"codec\":\"base32\"}", VaultSpec.class);
        final RSAVaultSpec constructed = new RSAVaultSpec("BASE32");

        assertEquals(fromJson, constructed);
        assertEquals(constructed, fromJson);
        assertEquals(fromJson.getAlgorithm(), constructed.getAlgorithm());

        final String json1 = mapper.writeValueAsString(fromJson);
        final String json2 = mapper.writeValueAsString(constructed);

        assertEquals(json1, json2);

        final VaultSpec fromJson1 = mapper.readValue(json1, VaultSpec.class);
        final VaultSpec fromJson2 = mapper.readValue(json2, VaultSpec.class);

        assertEquals(fromJson1, constructed);
        assertEquals(fromJson2, constructed);

        log.debug("RSA Vault Spec -> %s", json1);
    }

    @Test
    public void testCryptoSpecExtension() throws Exception {
        final AESCryptoSpec aesCryptoSpec = (AESCryptoSpec) mapper.readValue("{\"algorithm\":\"aes\",\"kdf\":{\"function\":\"openssl\"}}", CryptoSpec.class);
        final AESVaultSpec  aesVaultSpec =  (AESVaultSpec)  mapper.readValue("{\"algorithm\":\"aes\",\"kdf\":{\"function\":\"openssl\"},\"codec\":\"base64\"}", VaultSpec.class);

        assertTrue(aesCryptoSpec.equals(aesVaultSpec));
        assertFalse(aesVaultSpec.equals(aesCryptoSpec));

        final RSACryptoSpec rsaCryptoSpec = (RSACryptoSpec) mapper.readValue("{\"algorithm\":\"rsa\"}", CryptoSpec.class);
        final RSAVaultSpec  rsaVaultSpec =  (RSAVaultSpec)  mapper.readValue("{\"algorithm\":\"rsa\",\"codec\":\"base32\"}", VaultSpec.class);

        assertTrue(rsaCryptoSpec.equals(rsaVaultSpec));
        assertFalse(rsaVaultSpec.equals(rsaCryptoSpec));

    }

}
