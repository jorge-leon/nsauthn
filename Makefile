#
# Support for multiple NaviServer installations on a single host
#
ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Name of the modules
#
MODNAME = nsauthn

#
# List of components to be installed as the the Tcl module section
#
TCL =	init.tcl \
	passwd.tcl \
	ldap.tcl \
	README.md

#INCLUDED_IN_NAVISERVER = 50000

#
# Get the common Makefile rules
#
include  $(NAVISERVER)/include/Makefile.module
