heartdirect:
	$(CC) -c heartdirect.h -fomit-frame-pointer -o heartdirect.o -masm=intel

all: heartdirect
