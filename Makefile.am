AUTOMAKE_OPTIONS=-Wall foreign
#SUBDIRS = policies

OFSRC=@openflowsrc@

rundir = $(localstatedir)/run
AM_CFLAGS = -DRUNDIR=\"$(rundir)\" -Wall -Wshadow @LARGEFILES_CFLAGS@
AM_LDFLAGS = @LARGEFILES_LDFLAGS@


CFLAGS+=-I$(OFSRC)/include -I$(OFSRC)/lib -I/usr/include/ 
LDFLAGS+=-L$(OFSRC)/lib -lm -lpcap  -lpthread

LDADD=$(OFSRC)/lib/libopenflow.a -ldl 


bin_PROGRAMS=flowvisor
#bin_SCRIPTS=flowvisor_wrapper.pl

EXTRA_DIST = regress BUGS example-confs

flowvisor_SOURCES= flowvisor.c \
		utils.c \
		flowvisor.h\
		utils.h 


count: 
	@wc -l $(flowvisor_SOURCES) $(flowvisor_HEADERS) | sort -n
