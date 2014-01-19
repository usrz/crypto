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
        Assert.assertEquals(privateKey.getModulus(),         new BigInteger("e21080a07986b5536b8a6d178c5f2eedfdb26b42e6d1cfb4a8e47456171870ec7dd9ff0359c69ffebde863b5e146b3d25d352598b46052657fa18826a6996dfaf05da3f9b85026f10273f13b11b417cca61dd3d6b1705af6fd7e334b1ad234f6804dc85d89ead1875f7d9648a5d18d75e1f25eeac8ea90853a1bec3a6ad00780508d3121d33496c6162cdacb41d8ac1c98429c2d1bc6d43dc45cae5b55d498ff17285252e9c9c664ad957d8f738ddb7e18aecf7bcd78a0b8d442d8486af122c801dfba194e836f3694af9e67e6acc4e72208aedb26e0f222c873e30c8592acc7586b6d330966d78561ca963483f3e6ddfb5de75e2200bd332b7e0501f7f227c3a8da85f8c336d69dfb987289b604d63e9e385c5426cb35bbdcf188b50458a94ee8d1b943f656aca8424ef9b54497fbc8d15a69e82c22e2fadfa23b5a7d7d70bcf66e9de49bb60ef2884ee9e772e0fd3ea440a57b242cb2e9b9017da9993be5de0ae1208ea01b93035577d16d92bd0528f423b874b953c53410d81f048b3fb807e424dd99fb49e2f454aef4681d895d9591ac843dc51a52e1a3fc94896835c91060e3174adae6d221a67bd56c3afa01e2fde050049e068026691bc9f9011ed16183979ea89c557fdeefa0680163a5cc1d8b7937946b9559686154095bd0160062a7dd5bb6708573caca9e63a44035fbbbf6f480c9c392064a288aa29bcc1de497", 16));
        Assert.assertEquals(privateKey.getPrivateExponent(), new BigInteger("b63646f711fd1a3a5afc006272aa65d13e2389812b3b0207c3fa202b24027742a74e06d6548e5c779feaa833f9985b68bbe8129dbb05c8643733a3e2437677c743e6b63c99eb40f811da121e626e9ea03d64dd52b742b08f54535c54b511a9cee62bcbcc595603fcf162f0b72db0722d0a29a987e4d9ec12f67b7b34bad362b87234dbdd3fb7abaf8e40293a9ba06159cb002591d649b4d8f4651fc44eb2457f96d2d148335887a8aea147cb50808ee25c52caba272b8ba06eb6524e4ca4803c660646a20f3eb16d74faf8db167b3b5a717c3e34366a29c10f81190906c0eab2e2f9f3d2a749557e150c8d7556c648d7b3bc44b902ff4580f1156a43e3ee334d65f7849f8cc802ae68b200549897151e7257160050453cf730fa62f40b506514ab3cecc370a687f064869356675da836722121773115c59100d665dfd65a9e366f6e5549ccafffe991d52ef8fd30ebe8e94e4071885f368358cf615d9335342e589a3b6187f26869b7624065d20980d73610df2b2041801162efbb935c1f9ff6a7ca4013453b01c606874d2eed8e87f2380943b981a29e76911aaa3bcc0dd6429624233c189bcde8c6ca0a0630585fa0be55d9677fcd288c58415387e87faa4267e741972d8910f56b00757b7e26ecd3e85db74a2eb56ce64d558935dd3b496eb3046b2933cebdfd43b92a38319f488ebacb90d40a9040d9956bdd952aa74501", 16));
        Assert.assertEquals(privateKey.getPublicExponent(),  new BigInteger("010001", 16));
        Assert.assertEquals(privateKey.getPrimeP(),          new BigInteger("f4a29132c76d7ccb8a5bfc79215c8eef6b975306e0572c6494332b59692f1c671908ac65d647bb4095567dd87556f68d05c29e75bc6825ca6e47d234f71f1e6d1fbdd29cf1e9719c6689f190fd06953f5ee8ab1260d66156285c82028b649dbc0d30be7b1a8d5514d92eb19f0c895a5f26f2dc69af494533351113ab77756013df6eeb28bf9d4c5ef80c934e968cbb088b33773268bcc9773022701d3f7eac18601ddfc7bfd3b21c5b1959c26b05fc7871bfec7a6b201f8f4dad9de7115742d520d0bd77fb5442a9945a84f7bfb6580c42d49ae64f10d01a469420a5cafd1c2b37e234b12444e6f31b0352a96eb59eab3ad09bd2e05ba8f6f3aeae6ec6dfe951", 16));
        Assert.assertEquals(privateKey.getPrimeQ(),          new BigInteger("ec91138fbcb59e91c1d669b42fcc4ea61f90e800492dd64251c4f9afe6aa4df4f4071f16827c8b2c4bf8f3226d8883cc6f8dedfd606e0ed8673cae209e8c97515cb23e950017d86a2aecdc5abe620edafed31aa0dc11a974c8e30b2ce7d527017a72e9b713c8dc5d9a1e982635f35f42a759c68b86d1eec18838e189e3f8e307cadc72519223e39d6cb2b8ec44e5589cc41ebc9f1699028742cd411eb451adcff884bc38b9ccf5460e8a5fab8ba5a0b97467ebd483fc1642a9612a6f8c1a6f2c5768bcfc72ca1d768298a8b54238fc72926a39c716d20546392a6b00599c5e2d9b637df483ed2f76de4af02c6cf90189d6429f241db22435210f593eb2d57567", 16));
        Assert.assertEquals(privateKey.getPrimeExponentP(),  new BigInteger("7abbd4fd14f0e95b74df119bf410ebe552a569125a1b623a53e0182f9385ff49fa554fa9080894f9a1f2f2d0568e7ac3e5cfee9043263d4f8264a621cc99e039ff62ccf7d0a6be492968abb982387b487fe55b6ead06e16ec871210905c6451cc3c160cf8252c60cdfa97d93be466b00b219c65b7f85d3220dcdb380a33e5025a8438dd7b3cac7361e5cb0cb0cdd2e38eb1db6ffa36c93e7284f1ed08dba8fbceafc11f9b5541058099c7e5bfc35d4a4d8ece147c9d723fe518a795e24651332ba73ff9ae28d33a4c0b9695ca2e268ea3ddd4c999fb15fb6cf12220f0bf850d99dffef4fb052a14bf69184375d43e18726cae262ba0d42882359d049e39d1301", 16));
        Assert.assertEquals(privateKey.getPrimeExponentQ(),  new BigInteger("1381b2f73b3c4ea2fe34cbea8bb67115c9ac8d34d8d3eac2f53324d398559ab0041f4234fcf580145aff602d0a93232b0c57cbb404eb8e55d1cd731e45749a559f2b2375edd80984579dc85dc32d1ac47c16b42f67761d5effe198de4f0f8873dac0f6fc9da90662c17e9c552a45b3292fdb7b3fae124979b3dddcdb1ded3beb3c9308ea28fec49a0a88822f194f400b4d30aba5029c03555bf0c8d9db4c90e4813d90b7acba75cf1d0bd3efb5482704a3d09de59c2c813965f61925b18bcc76ff8e2767399fe8e608c6c5c28c7f5e71a4191642906329042d5a8e102d537380973b90fb44959e4052fc22e9c6e29179e82cfe2a60387c3bd54a0ab5dcd13529", 16));
        Assert.assertEquals(privateKey.getCrtCoefficient(),  new BigInteger("957ba46e9ca5801ff05ab2278ed995f3925753a786773e0ea743e0667eee8ba3756b3f6e7b855384c2fe2bb260d6747604e2861732e3d8d77cbbd45f995c9f66b14c0c4b7bf255ea732e27314bc28ceab0b39c2b295702fc7515f8021daead5f4deb94ce3c0603ebf827ff228f85b68604c6c0ca1cf2f79d1a4b2f350977717c379bd108d1adc95a32d737756cd9d33d2f2dab61f3206a138f9d51639f01f6077812df88c25daff773e5b133325037bb9438610580c9579e7ff13acaaeb25576349ab5bf11912634a0d72de6189be78d471965eebd931055ca6330eb2d1a5affdd47aad530357656e5608eb0e45140e08c1f68a632dcf3c1e28c09972322d1bd", 16));
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
        final byte[] data = HEX.decode("ad78851872de9a43f2e75bfa0f48c316078e1e2a5b9f241341b5721a7b397be0a6c666240c62f0147ab3af3989d1139084b682b848c2513b642b0c6177c5ac75e551b6dd40469cd268373db1bc60db83103e036f7857adff5a1f535714974262cbed349b59f39d857595ee7ce4857bd342553ca34bf02675cc1a1ea6c00747a02d56225a570d6db747a0cd7cfe9ad7d601d35bc81262a1a9dda7408e7fb5972bda8cefef3bb8b4eaf9385fd17168a930fb043138ccddc1962c19501c987dad2bf98407abfb93d665f732a9660255ccb784e250d48de7f72eb18097f83ddc051c28918232733385d14b71057cf28a3d6fd28610d0aa9df18a6f5b1d159ca313dcf6c5aa01fc1cd605bce3dd79a217221b7a0df0c5921b6452afee94b24fac6110961cba18bae86030f38a28b77ce19d660ac4ca486067185880f4de4ccb6e52fc85a2d1fb36a350703cb9eb28f430b259e31f5e96fa492a237f4178ba708654de407fcdd8a12e6aec4a32b7f79e7606a8984912fb0fdf49ce72738a21ec05c8dca9da324633739575331b52f58e8fbb4e1c39350001865132180e1c91c5173ec48301449ea663b909383662296978eaa26fad8e3ed4cd8b2bb9c760448edf85199d6884740d1a6df9499ccaa06f91f863ac055d7643ff00afc29f4546ced5b2114fa856038b83cc7f16c2efada840664486e782bad59f8ed3860bf492316bada5");

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
