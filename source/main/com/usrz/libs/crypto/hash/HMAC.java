package com.usrz.libs.crypto.hash;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

public class HMAC extends AbstractFunction<HMAC> {

    private final Mac mac;

    protected HMAC(Hash hash, Mac mac) {
        super(hash);
        assert (mac != null): "Null Mac";
        this.mac = mac;
    }

    public final Mac getMac() {
        return mac;
    }

    @Override
    public final HMAC reset() {
        mac.reset();
        return this;
    }

    @Override
    public HMAC update(byte[] input, int offset, int length) {
        mac.update(input, offset, length);
        return this;
    }

    @Override
    public void finish(byte[] output, int offset) {
        try {
            mac.doFinal(output, offset);
        } catch (ShortBufferException exception) {
            throw new IllegalArgumentException("Buffer too short", exception);
        }
    }

}
