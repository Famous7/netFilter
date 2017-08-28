all: netFilter

netFilter: netFilter.o
	gcc -o netFilter netFilter.o -lnetfilter_queue

netFilter.o: netFilter.c
	gcc -o netFilter.o -c netFilter.c
