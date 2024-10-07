heartdirect:
	$(CC) -c heartdirect.h -fomit-frame-pointer -o heartdirect.o -masm=intel -fomit-frame-pointer

all: heartdirect
