cp.so: main.c
	gcc -g -O0 -shared -o cp.so main.c -llua