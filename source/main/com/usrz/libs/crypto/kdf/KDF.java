package com.usrz.libs.crypto.kdf;

public interface KDF {

    public int getDerivedKeyLength();

    public byte[] deriveKey(byte[] password, byte[] salt);

    public void deriveKey(byte[] password, byte[] salt, byte[] output, int offset);

}
