DEPENDS = libecc/src/external_deps/print.o libecc/src/external_deps/time.o libecc/src/external_deps/rand.o
libsign = libecc/build/libsign.a

all:BN MuSig libecc example

BN:libecc src/BN.c src/BN.h
	gcc -c -I . src/BN.c -o output/BN.o

MuSig:libecc src/MuSig.c src/MuSig.h
	gcc -c -I . src/MuSig.c -o output/MuSig.o

libecc: libecc/*
	cd libecc;make

example:BN MuSig
	gcc -I . example/BN_secp256k1.c output/BN.o $(DEPENDS) $(libsign) -o output/BN_secp256k1
	gcc -I . example/MuSig_secp256k1.c output/MuSig.o $(DEPENDS) $(libsign) -o output/MuSig_secp256k1

clean:
	rm output/*
	