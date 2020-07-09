CC = gcc
CFLAGS = -Wall
TARGETS = testhttp_raw

all: $(TARGETS)

testhttp_raw.o: testhttp_raw.c
testhttp_raw: testhttp_raw.o

	$(CC) $(CFLAGS) $^ -o $@ -lpthread

clean:
	rm -f *.o *~ $(TARGETS)
