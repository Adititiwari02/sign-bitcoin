OBJECTS = main.o rand.o sha2.o hmac.o pbkdf2.o bip39.o

output: $(OBJECTS)
	gcc -o output $(OBJECTS)

main.o: main.c sha2.h rand.h
	gcc -c main.c

rand.o: rand.c rand.h
	gcc -c rand.c

sha2.o: sha2.c sha2.h memzero.h byte_order.h
	gcc -c sha2.c

hmac.o: hmac.c hmac.h memzero.h options.h
	gcc -c hmac.c

pbkdf2.o: pbkdf2.c pbkdf2.h hmac.h memzero.h sha2.h
	gcc -c pbkdf2.c

bip39.o: bip39.c bip39.h hmac.h memzero.h options.h rand.h pbkdf2.h sha2.h
	gcc -c bip39.c

clean:
	rm *.o *.h.gch output