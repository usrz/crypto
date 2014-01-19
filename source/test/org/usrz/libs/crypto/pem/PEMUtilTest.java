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

import static org.usrz.libs.crypto.codecs.CharsetCodec.UTF8;
import static org.usrz.libs.crypto.codecs.HexCodec.HEX;

import java.math.BigInteger;
import java.net.URL;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import org.testng.Assert;
import org.testng.annotations.Test;

public class PEMUtilTest {

    private void checkKey512(RSAPrivateCrtKey privateKey) {
        // Data gathered with -> openssl rsa -text -noout -in ./source/test/org/usrz/libs/crypto/pem/key512.pem
        Assert.assertNotNull(privateKey);
        Assert.assertEquals(privateKey.getModulus(),         new BigInteger("df9298bea3e11acec2e5f3911fee15928206a05e33cf523c7468572c87900b9e439ffbc1106959e2126696e262224de65e6d516210f9f5717f519b278aed2ff1", 16));
        Assert.assertEquals(privateKey.getPrivateExponent(), new BigInteger("4c5399fe0ba8c02432799aebc2c0df70831f8c045d1fbc6d933843fa99d55d8169205e075d9f696840d6a37685bc1545f0f1a7d42b3e32801b7ce3e1ca853359", 16));
        Assert.assertEquals(privateKey.getPublicExponent(),  new BigInteger("010001", 16));
        Assert.assertEquals(privateKey.getPrimeP(),          new BigInteger("f5a29657085413e65d76d97453f24d541d51d181436db8fd04f9d1908b2fb767", 16));
        Assert.assertEquals(privateKey.getPrimeQ(),          new BigInteger("e901af609b838fa07775ed32a2b7fd11dfcf7e703fa44a34617ad46216567ee7", 16));
        Assert.assertEquals(privateKey.getPrimeExponentP(),  new BigInteger("184895924f1978ca2a6d487c2e9c62b6b11b5899eddf980d3383bb0b0e278e7b", 16));
        Assert.assertEquals(privateKey.getPrimeExponentQ(),  new BigInteger("60836c2b6dff1e9cef1e8fb3aba6de526b0c3d692d5355d140976a257eef30fd", 16));
        Assert.assertEquals(privateKey.getCrtCoefficient(),  new BigInteger("12f7087d24d922f90e5b063548ea558b7f7fcc88b0dbb7295d66f70c8989b957", 16));
    }

    @Test
    public void testPrivateKey512()
    throws Exception {
        final URL url = this.getClass().getResource("key512.pem");
        checkKey512(PEMUtil.loadPrivateKey(url));
    }

    @Test
    public void testPrivateKey512_DES()
    throws Exception {
        final URL url = this.getClass().getResource("key512-des.pem");
        checkKey512(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPrivateKey512_DES3()
    throws Exception {
        final URL url = this.getClass().getResource("key512-des3.pem");
        checkKey512(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPrivateKey512_AES128()
    throws Exception {
        final URL url = this.getClass().getResource("key512-aes128.pem");
        checkKey512(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPrivateKey512_AES192()
    throws Exception {
        final URL url = this.getClass().getResource("key512-aes192.pem");
        checkKey512(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPrivateKey512_AES256()
    throws Exception {
        final URL url = this.getClass().getResource("key512-aes256.pem");
        checkKey512(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPublicKey512()
    throws Exception {
        final URL publicUrl = this.getClass().getResource("key512-public.pem");
        RSAPublicKey publicKey = PEMUtil.loadPublicKey(publicUrl);
        Assert.assertNotNull(publicKey);

        final URL privateUrl = this.getClass().getResource("key512.pem");
        RSAPrivateCrtKey privateKey = PEMUtil.loadPrivateKey(privateUrl);
        Assert.assertNotNull(privateKey);

        Assert.assertEquals(publicKey.getModulus(),        privateKey.getModulus());
        Assert.assertEquals(publicKey.getPublicExponent(), privateKey.getPublicExponent());
    }

    @Test
    public void testDecrypt512()
    throws Exception {
        final URL url = this.getClass().getResource("key512.pem");
        final RSAPrivateCrtKey privateKey = PEMUtil.loadPrivateKey(url, "asdf");

        // Generated with -> echo -n "Testing encryption at 512 bits" | openssl rsautl -encrypt -inkey ./source/test/org/usrz/libs/crypto/pem/key512.pem -pkcs
        final byte[] data = HEX.decode("521af34fa9ab2ad13cd8e59375c863ad78711ed2d52aa58303c2c4e63cfd6c345888a93559eb221e2ac1220bbe0939e98717c9dbb80c362d87463bdec4abf398");

        final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        final String result = new String(cipher.doFinal(data), UTF8);

        Assert.assertEquals(result, "Testing encryption at 512 bits");
    }

    /* ====================================================================== */

    private void checkKey4096(RSAPrivateCrtKey privateKey) {
        // Data gathered with -> openssl rsa -text -noout -in ./source/test/org/usrz/libs/crypto/pem/key4096.pem
        Assert.assertNotNull(privateKey);
        Assert.assertEquals(privateKey.getModulus(),         new BigInteger("e0e4d6d7bcd15e7928f871792109a0deb1a37fef2230e8e94f6055b675a313ca2aa9e2b12a722dc4c9377d82418af33c2b67fc5e5aae98cb84e04220b9e8a85a8ec8369c93bcf53538a543ca7abccd958f9360a898f0ddf901bff921d27aa8d0fdd3c551893084d7c1301fc2c5cf6c568d728bdcf25ecaad8bf2fd51577267c7ec906046ba1f472431c252c0b6f8d4d0d6f165517e6275f213f3727222db04fa2dcb51892e8a3faf664c4aa224eb39b3777ef072036b3aa2fcdbcd081ab75b9854cb66da0f609f3f0ed940abda35ecaeedd156314ba08486d18482895c4687bcf84447c73db16adddfe30a47f8ef285660318b18a5d6d63b67dbf49ab70a7f75520408d66bb705601ec9c39c5c53194c5661f334fc0037031b5ede010838c673ad722863d39c7adc35adc905976c21a1c76dd1e5e678107539f4919284661d8faf48f816e9ba4692203af917de68351696c2a5ffab6fd4dbc6169ed07324774c6774eff7cc616fc05562b6b948a3551718b2d39d1c444d1d1328f7573aae07b260e53fb539945f748ba2dfdfebf36cc276bb8ea2e30c56a40c2007f90e7ddb170e1cb5afed16bf6cf87d6a40ece161d8fd93fb4a49a5f302fccb56be33d7decde14268565b6a49ba1c16dc5a5169319d24ecfd6d133ada54500e9f0fadda9805b92a1f85b06bbca43dce02de6ba54c2ba50eb90228095d973f9371c734dfdcef", 16));
        Assert.assertEquals(privateKey.getPrivateExponent(), new BigInteger("5cca0e5ab4ed2dad8fd9f1f7a849f0b5f1552453e62787f1bb6e63ef045a64afe52a72fde62575fcdb88a9a034aabff0f377d4089a21afa94909be3f02759c00c1289a5fc0151696fee8313039b3ec9ee8be46034a17177ec5da0f50852756bfe3fa9c4f27eb7ce4083172e949f46b1ecafd97f77188ead6f00731bd7df7161ac6e04ad8e3b244080affc265011969b540fa1873a751b89848e309354e6c4f8169a399e09ff32a939401a64980320d7c9eb12143e96534ac4ae7e590927554b565470708b18f8c24d85b8af35cf522d28a0cf52321b0f8fd27352526c78bd23585b9a663ee7065476638a6e54b3061d4419c2f67dc04e81f5a9ac6318f942541dc7c17da6bbee20e92d872956704410737096ef51b1460d5e996b740abf29ef2541d330604d9577c6148579d83312dfce80576719f6bb4789394084691f4a117e771335f060568f91bb25c4d83a34533b2f51092d146b7d1dadbb20b5bac0b38562651a793845ecaae503d8e2a1a27bd82202ee0fe2aac41a45c1df626da651878f4867ea1a9306ee044cc642a0235cbd5d80f56134d54447b79195a99323bb7a749c10e738b64ef71ad4555706f398fd39eb9aef27373a814df1ef4ea92eaaa0d3d91347cd3118ed5be2a988c916b18e142fe2ce28b692a8bd48f82f568c127f36cf171aa3accb93d663a2c6ddadd6f4bff00a037816907532a195412ed5401", 16));
        Assert.assertEquals(privateKey.getPublicExponent(),  new BigInteger("010001", 16));
        Assert.assertEquals(privateKey.getPrimeP(),          new BigInteger("fb962fa6f4d2afb450933d3b0ac1e75573c6107f17bc7574882ab3b7a3882aa0ba286e87ddefa7020b89f1ad0cd4900fbd4d27865e3834ebe369b9e9744d15c4aef46751acc1716933635955d58b7b55fe089c4e2cdac2f7ad4bd885c55070a2ff5e313813d96de0891c23bf67be723ab47bffd0c1f7ea35990164ea427dcf3101280e0ee389600737dae70a4f42dceb9ea71979689efdf8d3ebe83b8a2ee77eee9e81f4b7338c722dd09bcc9b6e67f76e93cb052cc20c3c11a7989e320c89c8187b05570f15bfed544d9637a3e251c9c59916517d0f9eaf3c2385f0729df1036a7191b83925d570f6c4f992c4b3594724588021850eb01304207d2f8fcc5671", 16));
        Assert.assertEquals(privateKey.getPrimeQ(),          new BigInteger("e4d6c84f3db2373f738fd8a75cd6318d87dddfb1dbb129ad60cb07d4b955ebc21b6f39ad6188cf67b6f895d9f42f7dbeab477570980751a6588b2f443b775f8845040712dbae29b307b26f96b64c6f01ce92038f3e1d031dc8fc566ee778c52e647750a4b5637a9cb854184affb793908ef403f520edc3bbff2cb34672badcd54fdcb4f3d0f858926edc740dc0135405fed25d182f42dc498492732b9e3dc9b13d78f907f7894aa8c75fa31b0ad0cc723f7ce1ac9c1c31a66bd42e07ae1a819611b840e51c6427ed20bba33b4d1776e78db82ff86fc41dbf3c85f43dc89b91573e775f290017a2d84b4821a8959b7fac102dc575292ca93141f2fd17ae26d95f", 16));
        Assert.assertEquals(privateKey.getPrimeExponentP(),  new BigInteger("7fb10f888eb42c87b969b1e738a387f5802864110d8c12954dd35699fb3f4e5b7b80aff0f7bcfe27f49153ff80069703d611c5e0d60b7318d2b8c3aa70e3fb0b73bd0a7f92ce2ff0b42b55995224543a26105abcf6d925a1adec53fe39528588c5521a6b1aeffd6bbc4b72fd5ffb7260c760344bd1573221780214252e104acbd5896df1329d7406d5db9dee46a26a1c90cec10835089560e8b6d08cffaaa4c670f8347f6f48939d1411d031be260050be67f6e02e8262d14e28a13691b2796ffcb4dbd5ff0b0bf9ba13130e3478d70830e96d4178d727b44b32c07574c7231f97b402c0dd088dd7a2f800aff4740ef923c2636e1fe97f86774ec21b14c22291", 16));
        Assert.assertEquals(privateKey.getPrimeExponentQ(),  new BigInteger("e00537510387dcb7fc0c5cbef28e293271488e3d52616bf873e22e475c2c35c0ef1482752e1f3d533df6bad4044d1d9f33939fef5a9507a47dd7bbace33e284281b5c0ab006dce1a9a355f323e423305a4d0a2356f4bfd8a0200ad28a2e742b8f8d7291625103eaeff702bdbf7dc21d4896d6e166167018f9fed858f38af9f921f3d63d3afc5ff075309f37ea68305655d2158cb5d30e9effa9d57abe29c803f477b8ee6f2b7ef63acd1fe1d720817acdc640794efba560ca250b3c306f8a1d5648168de215e170bf7585922ab8485fd866a4263c61e4a34b52e397ce64f0d08487999a9cc9256f3c136dae46b992f7224e07a060909d4940908b425a3721aa7", 16));
        Assert.assertEquals(privateKey.getCrtCoefficient(),  new BigInteger("f872ff2418812f5b90d70a467d82352e1a2909f06c60cdf9f6f1528d45a0c30cb79e9345f9fa0ed99cff58b928dea782d75535feace2c97be8bd4ab03842ec5182a1dbe11482bd5fe4746eadf10ac4bb1b631a4b578d0fe1029312001b6e2fa5bc9b3e1de7c87584713d7b1ee3313516796a36a01a2d5f35cb775379ca4754a480d7d1f9a15cc9ab2592bd6d02d8684f10a291377fb22a18a153db8c93100dc1fdeb0c85af738fc98896290fb117d1639f33057773d6e3cae18a3cdc9b702ff7721a3ffd8ecf3073bc8c3316a9dcb7eb1f5ba0dad5cb9739214f7162aa9741063a826f908b430d4357397708f2334104120a7276d47b2cba137bace08d40d4af", 16));
    }

    @Test
    public void testPrivateKey4096()
    throws Exception {
        final URL url = this.getClass().getResource("key4096.pem");
        checkKey4096(PEMUtil.loadPrivateKey(url));
    }

    @Test
    public void testPrivateKey4096_DES()
    throws Exception {
        final URL url = this.getClass().getResource("key4096-des.pem");
        checkKey4096(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPrivateKey4096_DES3()
    throws Exception {
        final URL url = this.getClass().getResource("key4096-des3.pem");
        checkKey4096(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPrivateKey4096_AES128()
    throws Exception {
        final URL url = this.getClass().getResource("key4096-aes128.pem");
        checkKey4096(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPrivateKey4096_AES192()
    throws Exception {
        final URL url = this.getClass().getResource("key4096-aes192.pem");
        checkKey4096(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPrivateKey4096_AES256()
    throws Exception {
        final URL url = this.getClass().getResource("key4096-aes256.pem");
        checkKey4096(PEMUtil.loadPrivateKey(url, "asdf"));
    }

    @Test
    public void testPublicKey4096()
    throws Exception {
        final URL publicUrl = this.getClass().getResource("key4096-public.pem");
        RSAPublicKey publicKey = PEMUtil.loadPublicKey(publicUrl);
        Assert.assertNotNull(publicKey);

        final URL privateUrl = this.getClass().getResource("key4096.pem");
        RSAPrivateCrtKey privateKey = PEMUtil.loadPrivateKey(privateUrl);
        Assert.assertNotNull(privateKey);

        Assert.assertEquals(publicKey.getModulus(),        privateKey.getModulus());
        Assert.assertEquals(publicKey.getPublicExponent(), privateKey.getPublicExponent());
    }

    @Test
    public void testDecrypt4096()
    throws Exception {
        final URL url = this.getClass().getResource("key4096.pem");
        final RSAPrivateCrtKey privateKey = PEMUtil.loadPrivateKey(url, "asdf");

        // Generated with -> echo -n "Testing encryption at 4096 bits" | openssl rsautl -encrypt -inkey ./source/test/org/usrz/libs/crypto/pem/key4096.pem -pkcs
        final byte[] data = HEX.decode("add78391c43565744cec22c61988ff3a25621179195e47ffb61ba2aba069233cbefde5290c8139fe3f2bb7c35f44b387f8765e49a8e60fe668b6a0804697c4aba0b9ea81fcca9462745d0dd6588ab42ccd929b8958708bf44e356b309f16c2699362baae804410956858aa3d799156abd5955dd37965f2c70b74a8eb025d279deed6b308039d19ee52e3f56cd132f5bc029cd75ec51c03c331ae33156765e5be171e1c5d944c654423e654b96702648af41c8ff84ac63cdb4f88b0d241605b24d5d0cdf420160c7ed8c9e33a9cc201043e709760de4a9d475d6bbc1149fb9719b60fd2b0b5cf5ed73270d0638120c4816ee4eb37937d1743c753ff0389119de710671601fd6a3b47959bc6c4b48df872852db4798fde166e34a6d52450149118c77c905390b7622b495c97de72a7b4b61c2545daa442c310098a9e627c49b6de2daa58c77cdf21eac192d5fb1b126b0c51362d8a600f71369127f95e0964dc76ebe0e3bfc87b895b3829094cd631462cb4fbe1fd6faccae793d4c6b1822ce73bb41fe45756105bbb119c3b64eb547bf52ec021938bfef4b7442d07dac934bafa23e1bf1cab4a479358447b1be00d15886938c790ddcc5c4f839515e09929d1dee01ef512817d018ec0ab3e6e136d789789647668afbd181bcd569753a25de0174352631d19357169c7cf1bcb0e4550fd149ad7531a3014ef0f2bb45093081a82");

        final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        final String result = new String(cipher.doFinal(data), UTF8);

        Assert.assertEquals(result, "Testing encryption at 4096 bits");
    }

    /* ====================================================================== */

    private final Principal www_google_com = new X500Principal("CN=www.google.com, O=Google Inc, L=Mountain View, ST=California, C=US");
    private final Principal google_auth_g2 = new X500Principal("CN=Google Internet Authority G2, O=Google Inc, C=US");
    private final Principal geotrust_ca    = new X500Principal("CN=GeoTrust Global CA, O=GeoTrust Inc., C=US");
    private final Principal equifax_ca     = new X500Principal("OU=Equifax Secure Certificate Authority, O=Equifax, C=US");

    @Test
    public void testCertificate()
    throws Exception {
        final URL url = this.getClass().getResource("certificate.pem");
        final List<X509Certificate> certificates = PEMUtil.loadCertificates(url);

        Assert.assertNotNull(certificates);
        Assert.assertEquals(certificates.size(), 1);

        final X509Certificate certificate = certificates.get(0);
        Assert.assertNotNull(certificate);
        Assert.assertEquals(certificate.getSubjectX500Principal(), www_google_com);
        Assert.assertEquals(certificate.getIssuerX500Principal(), google_auth_g2);
    }

    @Test
    public void testChain()
    throws Exception {
        final URL url = this.getClass().getResource("chain.pem");
        final List<X509Certificate> certificates = PEMUtil.loadCertificates(url);

        Assert.assertNotNull(certificates);
        Assert.assertEquals(certificates.size(), 3);

        final X509Certificate certificate0 = certificates.get(0);
        Assert.assertNotNull(certificate0);
        Assert.assertEquals(certificate0.getSubjectX500Principal(), www_google_com);
        Assert.assertEquals(certificate0.getIssuerX500Principal(), google_auth_g2);

        final X509Certificate certificate1 = certificates.get(1);
        Assert.assertNotNull(certificate1);
        Assert.assertEquals(certificate1.getSubjectX500Principal(), google_auth_g2);
        Assert.assertEquals(certificate1.getIssuerX500Principal(), geotrust_ca);

        final X509Certificate certificate2 = certificates.get(2);
        Assert.assertNotNull(certificate2);
        Assert.assertEquals(certificate2.getSubjectX500Principal(), geotrust_ca);
        Assert.assertEquals(certificate2.getIssuerX500Principal(), equifax_ca);
    }

}
