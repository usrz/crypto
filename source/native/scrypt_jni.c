// Copyright (C) 2011 - Will Glozer.  All rights reserved.

#include <errno.h>
#include <stdlib.h>
#include <inttypes.h>

#include <jni.h>
#include "crypto_scrypt.h"

void JNICALL scrypt_jni(JNIEnv *env,
                        jclass cls,
                        jbyteArray passwd,
                        jbyteArray salt,
                        jbyteArray out,
                        jint offset,
                        jint length,
                        jint N,
                        jint r,
                        jint p)
{

    jint Plen = -1, Slen = -1;
    jbyte *P = NULL, *S = NULL;
    uint8_t *buf = NULL;

    /* Check our parameters */
    if (passwd == NULL || salt == NULL || out == NULL) {
      jclass e = (*env)->FindClass(env, "java/lang/NullPointerException");
      (*env)->ThrowNew(env, e, "Invalid parameter passed to native SCrypt");
      goto cleanup;
    }

    /* Get our buffers and buffer lengths */
    Plen = (*env)->GetArrayLength(env, passwd);
    Slen = (*env)->GetArrayLength(env, salt);
    P = (*env)->GetByteArrayElements(env, passwd, NULL);
    S = (*env)->GetByteArrayElements(env, salt,   NULL);

    if (P == NULL || S == NULL)  {
      jclass e = (*env)->FindClass(env, "java/lang/InternalError");
      (*env)->ThrowNew(env, e, "Unable to get array elements in native SCrypt");
      goto cleanup;
    }

    /* Allocate some memory for our processing */
    buf = malloc(sizeof(uint8_t) * length);

    if (buf == NULL) {
      jclass e = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
      (*env)->ThrowNew(env, e, "Memory allocation for SCrypt failed");
      goto cleanup;
    }

    /* Yay! Go ahead */
    if (crypto_scrypt((uint8_t *) P, Plen, (uint8_t *) S, Slen, N, r, p, buf, length)) {
        jclass e;
        char *msg;
        switch (errno) {
            case EINVAL:
                e = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
                msg = "Invalid parameters passed to native SCrypt";
                break;
            case EFBIG:
            case ENOMEM:
                e = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
                msg = "Insufficient memory available";
                break;
            default:
                e = (*env)->FindClass(env, "java/lang/IllegalStateException");
                msg = "Unknown error in native SCrypt";
        }
        (*env)->ThrowNew(env, e, msg);
        goto cleanup;
    }

    /* Fill the Java array with the result of our process */
    (*env)->SetByteArrayRegion(env, out, offset, length, (jbyte *) buf);

  cleanup:

    /* Cleanup before getting back */
    if (P) (*env)->ReleaseByteArrayElements(env, passwd, P, JNI_ABORT);
    if (S) (*env)->ReleaseByteArrayElements(env, salt,   S, JNI_ABORT);
    if (buf) free(buf);
}

static const JNINativeMethod methods[] = {
    { "scrypt", "([B[B[BIIIII)V", (void *) scrypt_jni }
};

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;

    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    jclass cls = (*env)->FindClass(env, "org/usrz/libs/crypto/kdf/SCryptNativeHelper");
    int r = (*env)->RegisterNatives(env, cls, methods, 1);

    return (r == JNI_OK) ? JNI_VERSION_1_6 : -1;
}
