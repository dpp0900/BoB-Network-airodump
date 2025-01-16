install:
	gcc -o my_dump main.c -lpcap

clean:
	rm -f my_dump