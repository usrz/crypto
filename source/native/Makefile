SYSTEM    ?= $(shell uname -s)
CC        ?= gcc
JAVA_HOME ?= $(realpath $(dir $(realpath $(shell which java)))../)

CFLAGS    ?= -fPIC -g -O2
CFLAGS    += -I. -I$(JAVA_HOME)/include

OBJS       = crypto_scrypt-sse.o sha256.o scrypt_jni.o

ifeq ($(SYSTEM), Darwin)
	LDFLAGS += -dynamiclib
  CFLAGS  += -I$(JAVA_HOME)/include/darwin
  LIB      = libscrypt_jni.dylib

else ifeq ($(SYSTEM), Linux)
	LDFLAGS += -shared
  CFLAGS  += -I$(JAVA_HOME)/include/darwin
  LIB      = libscrypt_jni.so

else
	$(error Unsupported system $(SYSTEM))

endif

all: $(LIB)

$(LIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $(LIB) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(LIB)
