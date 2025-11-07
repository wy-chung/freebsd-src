default: logstest.out 

logstest.out: logstest.o g_logstor.o
	cc -g -o logstest.out logstest.o g_logstor.o

g_logstor.o: g_logstor.c g_logstor.h GNUmakefile
	cc -g -c -Wall -DTEST_USER g_logstor.c

logstest.o: logstest.c g_logstor.h GNUmakefile
	cc -g -c -Wall logstest.c

clean:
	rm *.o *.out *.core

