CPP=g++
CFLAGS=-g -Wall

all: sumiserv

launch:
	$(CPP) $(CFLAGS) launch.cpp -o launch
	chmod 4755 launch
	sudo chown root launch

clean:
	rm -f sumiserv
	rm -f sumiserv.o
	rm -f md5.o
	rm -f launch

sumiserv: sumiserv.o md5.o
	$(CPP) -o sumiserv sumiserv.o ../irc/irc.o ../endpoint/endpoint.o ../endpoint/address.o md5.o
	# chmod 4755 sumiserv
	# sudo chown root sumiserv

sumiserv.o:
	$(CPP) $(CFLAGS) sumiserv.cpp -o sumiserv.o -c

md5.o:
	$(CPP) md5.cpp -o md5.o -c
