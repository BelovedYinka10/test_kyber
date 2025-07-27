# This Makefile can be used with GNU Make or BSD Make

LIB = libml-kem-512_clean.a
HEADERS = api.h cbd.h indcpa.h kem.h ntt.h params.h poly.h polyvec.h reduce.h symmetric.h verify.h
OBJECTS = cbd.o indcpa.o kem.o ntt.o poly.o polyvec.o reduce.o symmetric-shake.o verify.o

# Cross Compiler for ARM Cortex-A9 (QEMU vexpress-a9)
CC = arm-linux-gnu-gcc
AR = arm-linux-gnu-ar
CFLAGS = -O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls \
         -std=c99 -I../../../common $(EXTRAFLAGS) -march=armv7-a -mfpu=neon -mfloat-abi=softfp

all: $(LIB)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
