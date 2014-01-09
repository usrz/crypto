package com.usrz.libs.crypto.hash;

public interface HashFunction<F extends HashFunction<F>> {

    public Hash getHash();

    public int getHashLength();

    public F update(byte input);

    public F update(byte[] input);

    public F update(byte[] input, int offset, int length);

    public byte[] finish();

    public void finish(byte[] output, int offset);

    public F reset();

}
