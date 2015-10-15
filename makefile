
all:
	g++ -Wall -o wiretap wiretap.cpp callback.cpp -lpcap -g
