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
package org.usrz.libs.crypto.cert;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;

/**
 * A simple builder to create {@linkplain X500Principal X.500 principals}.
 *
 * <p>At least one attribute, the {@linkplain #commonName(String) common name}
 * must be specified prior to {@linkplain #build() building}.</p>
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class X500PrincipalBuilder {

    /* OID 2.5.4.3 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier COMMON_NAME = RFC4519Style.cn;
    /* OID 2.5.4.6 - StringType(SIZE(2)) */
    private static final ASN1ObjectIdentifier COUNTRY = RFC4519Style.c;
    /* OID 2.5.4.8 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier STATE = RFC4519Style.st;
    /* OID 2.5.4.7 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier LOCALITY = RFC4519Style.l;
    /* OID 2.5.4.10 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier ORGANISATION = RFC4519Style.o;
    /* OID 2.5.4.11 - StringType(SIZE(1..64)) */
    private static final ASN1ObjectIdentifier ORGANISATIONAL_UNIT = RFC4519Style.ou;
    /* OID 1.2.840.113549.1.9.1 - IA5String */
    private static final ASN1ObjectIdentifier EMAIL_ADDRESS = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;
    /* Order! */
    private static final ASN1ObjectIdentifier[] ORDER = new ASN1ObjectIdentifier[]
            { COUNTRY, STATE, LOCALITY, ORGANISATION, ORGANISATIONAL_UNIT, COMMON_NAME, EMAIL_ADDRESS };
//          { EMAIL_ADDRESS, COMMON_NAME, ORGANISATIONAL_UNIT, ORGANISATION, LOCALITY, STATE, COUNTRY };

    private final Map<ASN1ObjectIdentifier, ASN1Primitive> attributes;

    /**
     * Create a new {@link X500PrincipalBuilder} instance.
     */
    public X500PrincipalBuilder() {
        attributes = new HashMap<>();
    }

    /**
     * Create a new {@link X500PrincipalBuilder} instance.
     *
     * @throws IllegalStateException If an error occurred.
     */
    public X500Principal build() {
        if (attributes.isEmpty()) throw new IllegalStateException("No attributes specified");
        if (!attributes.containsKey(COMMON_NAME))  throw new IllegalStateException("Common Name not specified");

        final X500NameBuilder builder = new X500NameBuilder();
        for (ASN1ObjectIdentifier key: ORDER) {
            final ASN1Primitive value = attributes.get(key);
            if (value != null) builder.addRDN(key, value);
        }
        try {
            return new X500Principal(builder.build().getEncoded());
        } catch (IOException exception) {
            throw new IllegalStateException("I/O error generating principal", exception);
        }
    }

    /**
     * Specifiy the <em>common name</em> <small>(OID 2.5.4.3)</small>.
     */
    public X500PrincipalBuilder commonName(String commonName) {
        attributes.put(COMMON_NAME, toDERUTF8String(commonName, 64));
        return this;
    }

    /**
     * Specifiy the <em>country</em> <small>(OID 2.5.4.6)</small>.
     */
    public X500PrincipalBuilder country(String country) {
        if (country == null) throw new NullPointerException("Null country");
        if (country.length() == 0) throw new IllegalArgumentException("Empty country");
        if (country.length() != 2) throw new IllegalArgumentException("Country must be 2 characters long");
        attributes.put(COUNTRY, new DERPrintableString(country, true));
        return this;
    }

    /**
     * Specifiy the <em>state</em> <small>(OID 2.5.4.8)</small>.
     */
    public X500PrincipalBuilder state(String state) {
        attributes.put(STATE, toDERUTF8String(state, 64));
        return this;
    }

    /**
     * Specifiy the <em>locality</em> <small>(OID 2.5.4.7)</small>.
     */
    public X500PrincipalBuilder locality(String locality) {
        attributes.put(LOCALITY, toDERUTF8String(locality, 64));
        return this;
    }

    /**
     * Specifiy the <em>organisation</em> <small>(OID 2.5.4.10)</small>.
     */
    public X500PrincipalBuilder organisation(String organisation) {
        attributes.put(ORGANISATION, toDERUTF8String(organisation, 64));
        return this;
    }

    /**
     * Specifiy the <em>organisational unit</em> <small>(OID 2.5.4.11)</small>.
     */
    public X500PrincipalBuilder organisationalUnit(String organisationalUnit) {
        attributes.put(ORGANISATIONAL_UNIT, toDERUTF8String(organisationalUnit, 64));
        return this;
    }

    /**
     * Specifiy the <em>email address</em> <small>(OID 1.2.840.113549.1.9.1)</small>.
     */
    public X500PrincipalBuilder emailAddress(String emailAddress) {
        if (emailAddress == null) throw new NullPointerException("Null value");
        if (emailAddress.length() == 0) throw new IllegalArgumentException("Empty value");
        if (emailAddress.length() > 128) throw new IllegalArgumentException("Value too long (max=128)");
        attributes.put(EMAIL_ADDRESS, new DERIA5String(emailAddress, true));
        return this;
    }

    /* ====================================================================== */

    private DERUTF8String toDERUTF8String(String string, int maxLength) {
        if (string == null) throw new NullPointerException("Null value");
        if (string.length() == 0) throw new IllegalArgumentException("Empty value");
        if (string.length() > maxLength) throw new IllegalArgumentException("Value too long (max=" + maxLength + ")");
        return new DERUTF8String(string);
    }
}
