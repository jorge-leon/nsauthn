#
# License here
#

#
# modules/nsauthn/init.tcl
#

ns_log notice "loading nsauthn"

namespace eval authn {
    set Version 0.1
}

# Utility procedures

proc authn::matchURL {URL Match} {

    # Return true if $URL matches $Match, otherwise false
    #
    # Match:
    # /path/  ..   /path/* or /path exact
    # /path*  ..   string match $URL
    
    if {[string index $Match end] ne "/"} {return [string match $Match $URL]}
    if {[string trimright $URL /] eq [string range $Match 0 end-1]} {return true}
    return [string match ${Match}* $URL]
}

proc authn::unauthorized Message {
    # Err out of caller with $Message

    upvar Optional Optional LogCredentials LogCredentials LogLevel LogLevel User User Password Password
    if {$Optional} {
	set Code continue
	append Message ", continue to next filter"
    } else {
	set Code break
    }	
    set Credentials [expr {$LogCredentials ? "$User:$Password" : "$User"}]
    ns_log $LogLevel "$Message: $Credentials"
    return -level 2 -code $Code UNAUTHORIZED
}

proc authn::forbidden Message {
    # Err out of caller with $Message

    upvar Optional Optional LogLevel LogLevel
    if {$Optional} {
	set Code continue
	append Message ", continue to next filter"
    } else {
	set Code break
    }	
    ns_log $LogLevel "$Message"
    return -level 2 -code $Code FORBIDDEN
}

proc authn::registerProc {UrlPattern Config Success Proc} {
    if {$Success ni {optional required ""}} {
	error "success flag must be either empty, `optional' or `required', got: $Success"
    }
    ns_register_auth request $Proc $UrlPattern $Config [expr {$Success eq "optional"}]
}

# passwd initialization

proc authn::initPasswdCache Config {
    # Read in passwd file from  authn/passwd/$Config if not already loaded

    if {![nsv_dict exists authn passwd $Config :mtime]} {
	ns_log notice [info level 0]
	readPasswd $Config
    }
}

proc authn::readPasswd Config {
    # Read passwd file config ns/module/autn/passwd/$Config into
    # nsv_dict authn passwd $Config
    
    set Section ns/module/authn/passwd/$Config
    set Path [file join conf [ns_config $Section passwd passwd]]
    
    if {![ns_filestat $Path Stat]} {
	error "nsauthn: cannot stat $Config passwd file: $Path"
    }
    set LogLevel [ns_config ns/server/[ns_info server]/module/authn/passwd loglevel debug]
    set Fd [open $Path]
    ns_log $LogLevel "nsauthn: reading $Config passwd file from $Path"
    set Count 0
    while {[gets $Fd Line]!=-1} {
	lassign [split $Line :] User Hash
	nsv_dict set authn passwd $Config $User $Hash
	incr Count
    }
    ns_log $LogLevel "nsauthn: cached $Count user records"
    close $Fd
    
    nsv_dict set authn passwd $Config :mtime $Stat(mtime)
}

proc authn::getHash {User Config} {
    # Return password Hash for $User, or empty string if $User does not exist.
    #
    # If passwd file has changed it is reloaded, the path is obtained
    # from ns/module/authn/passwd/$Config. If reloading fails an empty
    # string is returned.
    
    set Section ns/module/authn/passwd/$Config
    set Path [file join conf [ns_config $Section passwd passwd]]
    if {![ns_filestat $Path Stat]} {
	ns_log error "nsauthn: cannot stat $Config passwd file: $Path"
	return
    }
    if {[nsv_dict get authn passwd $Config :mtime] != $Stat(mtime)} {
	ns_log notice "nsauthn: reloading $PasswdId passwd file from $Path"
	readPasswd $Section
    }
    nsv_dict getdef authn passwd $Config $User ""
}

proc authn::initPasswd Server {
    set Section ns/server/[ns_info server]/module/authn/passwd
    set LogLevel [ns_config $Section loglevel debug]
    foreach {Key Map} [ns_set array [ns_configsection $Section]] {
        if {$Key ne "map"} continue
	ns_log $LogLevel "authn: register passwd auth: $Map"
	lassign $Map UrlPattern Config Success
	initPasswdCache $Config
	registerProc $UrlPattern $Config $Success ::authn::passwd
    }
}

# ldap initialization

proc authn::initLdap Server {
    set Section ns/server/[ns_info server]/module/authn/ldap
    set LogLevel [ns_config $Section loglevel debug]
    foreach {Key Map} [ns_set array [ns_configsection $Section]] {
        if {$Key ne "map"} continue
	ns_log $LogLevel "authn: register ldap auth: $Map"
	registerProc {*}$Map ::authn::ldap
    }
}

# Init
proc authn::init {} {
    set Server [ns_info server]

    foreach {Type Proc} {
	passwd initPasswd
	ldap initLdap
    } {
	set Section ns/server/[ns_info server]/module/authn/$Type
	set Set [ns_configsection $Section]
	if {[ns_set find $Set map]!=-1} {
	    ns_log notice "init $Type"
	    $Proc $Server
	}
    }
}

authn::init

ns_log notice "nsauthn loaded"
