package com.usrz.libs.crypto.codecs;

public abstract class AbstractCodec implements Codec {

    protected static final String EMPTY_STRING = "".intern();

    protected static final byte[] EMPTY_ARRAY = new byte[0];

    @Override
    public String encode(final byte[] data) {
        return encode(data, 0, data.length);
    }

}
