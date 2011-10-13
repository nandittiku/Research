SFSLITEPATH = ../
INCFLAGS = -I$(SFSLITEPATH)sfslite-1.2.7 -I$(SFSLITEPATH)sfslite-1.2.7/async -I$(SFSLITEPATH)sfslite-1.2.7/libtame
LINKFLAGS = -L$(SFSLITEPATH)sfslite-1.2.7/async/.libs -L$(SFSLITEPATH)sfslite-1.2.7/libtame/.libs -L$(SFSLITEPATH)sfslite-1.2.7/sfsmisc/.libs -L $(SFSLITEPATH)sfslite-1.2.7/libaapp/.libs/  -L $(SFSLITEPATH)sfslite-1.2.7/libsafeptr/.libs/ -L $(SFSLITEPATH)sfslite-1.2.7/arpc/.libs/ -L $(SFSLITEPATH)sfslite-1.2.7/svc/.libs/ -L $(SFSLITEPATH)sfslite-1.2.7/crypt/.libs/ -lasync -ltame -lsfsmisc -lsafeptr -laapp -larpc -lsvc -lsfscrypt -lresolv 
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
