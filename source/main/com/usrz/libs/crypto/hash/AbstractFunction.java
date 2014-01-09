package com.usrz.libs.crypto.hash;

public abstract class AbstractFunction<F extends AbstractFunction<F>>
implements HashFunction<F> {

    private final Hash hash;

    protected AbstractFunction(Hash hash) {
        assert (hash != null): "Hash is null";
        this.hash = hash;
    }

    @Override
    public final Hash getHash() {
        return hash;
    }

    @Override
    public final int getHashLength() {
        return hash.getHashLength();
    }

    /* ====================================================================== */

    @Override
    public final F update(byte input) {
        return update(new byte[] { input }, 0, 1);
    }

    @Override
    public final F update(byte[] input) {
        return update(input, 0, input.length);
    }

    @Override
    public final byte[] finish() {
        final byte[] result = new byte[getHashLength()];
        finish(result, 0);
        return result;
    }

}
