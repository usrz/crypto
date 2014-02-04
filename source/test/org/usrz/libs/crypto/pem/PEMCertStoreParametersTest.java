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

import java.io.InputStream;
import java.security.cert.CertStore;

import org.testng.Assert;
import org.testng.annotations.Test;

public class PEMCertStoreParametersTest {

    @Test
    public void testCertStore()
    throws Exception {
        final InputStream input = this.getClass().getResourceAsStream("chains.pem");

        final PEMCertStoreParameters params = new PEMCertStoreParameters(input);
        final CertStore certStore = CertStore.getInstance("Collection", params);

        Assert.assertEquals(certStore.getCertificates(null).size(), 12, "Wrong number of certificates found");
        Assert.assertEquals(certStore.getCRLs(null).size(), 0, "Wrong number of CRLs");

        params.read(this.getClass().getResourceAsStream("full.pem"));
        Assert.assertEquals(certStore.getCertificates(null).size(), 15, "Wrong number of certificates found");
        Assert.assertEquals(certStore.getCRLs(null).size(), 0, "Wrong number of CRLs");

        params.read(this.getClass().getResourceAsStream("crl.pem"));
        Assert.assertEquals(certStore.getCertificates(null).size(), 15, "Wrong number of certificates found");
        Assert.assertEquals(certStore.getCRLs(null).size(), 1, "Wrong number of CRLs");
    }
}
