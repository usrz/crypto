package com.usrz.libs.crypto.codecs;

public interface Codec {

    public String encode(byte[] data);

    public String encode(byte[] data, int offset, int length);

    public byte[] decode(String data)
    throws IllegalArgumentException;

}
