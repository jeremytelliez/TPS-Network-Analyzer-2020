main:
	gcc analyseur.c analyseur.h -o analyseur -lpcap

clean:
	rm -rf analyseur
