GCC=g++
CFLAGS=-g -Wall

all: launch

launch:
	$(GCC) $(CFLAGS) launch.cpp -o launch
	chmod 4755 launch
	sudo chown root launch

clean:
	rm -f launch

