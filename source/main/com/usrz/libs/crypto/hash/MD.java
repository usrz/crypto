package com.usrz.libs.crypto.hash;

import java.security.DigestException;
import java.security.MessageDigest;

public class MD extends AbstractFunction<MD> {

    private final MessageDigest digest;

    protected MD(Hash hash, MessageDigest digest) {
        super(hash);
        assert (digest != null): "Null MessageDigest";
        this.digest = digest;
    }

    public final MessageDigest getMessageDigest() {
        return digest;
    }

    @Override
    public final MD reset() {
        digest.reset();
        return this;
    }

    @Override
    public MD update(byte[] input, int offset, int length) {
        digest.update(input, offset, length);
        return this;
    }

    @Override
    public void finish(byte[] output, int offset) {
        if (output.length - getHashLength() < offset)
            throw new IllegalArgumentException("Buffer too short");
        try {
            digest.digest(output, offset, getHashLength());
        } catch (DigestException exception) {
            digest.reset();
            throw new IllegalStateException("Digest Exception", exception);
        }
    }

}
