INCFLAGS = -Isfslite-1.2.7 -Isfslite-1.2.7/async -Isfslite-1.2.7/libtame
LINKFLAGS = -Lsfslite-1.2.7/async/.libs -Lsfslite-1.2.7/libtame/.libs -Lsfslite-1.2.7/sfsmisc/.libs -L sfslite-1.2.7/libaapp/.libs/  -L sfslite-1.2.7/libsafeptr/.libs/ -L sfslite-1.2.7/arpc/.libs/ -L sfslite-1.2.7/svc/.libs/ -L sfslite-1.2.7/crypt/.libs/ -lasync -ltame -lsfsmisc -lsafeptr -laapp -larpc -lsvc -lsfscrypt -lresolv 
CFLAGS = -g -Wall 

PREC := $(wildcard *.C)
TARGETS := $(PREC:%.C=%)

all : $(TARGETS)

$(TARGETS) : % : %.o
		g++ $(CFLAGS) -o $@ $< $(LINKFLAGS)

%.o : %.C
		g++ $(CFLAGS) -c $< $(INCFLAGS)

clean :
		rm -f core* *.o $(TARGETS)
