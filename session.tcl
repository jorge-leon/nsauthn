#
# License here
#

#
# modules/nsauthn/sesion.tcl
#

proc authn::session {Stage args} {
    # Checks if session cookie is present and valid.
    # Register as preauth filter.

    if {$Stage ne "preauth"} {
	error "invalid configuration, called in stage: $Stage"
    }
    set SessionCookie [ns_config ns/server/[ns_info server]/authn/session cookie nsauthn_session]
    set Location [ns_config ns/server/[ns_info server]/authn/session authlocation ""]
    if {![string length $Location]} {
	error "invalid configuration, no auth redirect location configured"
    }

    set Headers [ns_conn headers]
    set Cookies [concat {*}[ns_set get -all -nocase $Headers Cookie]]
    set Session ""
    foreach Cookie [split $Cookies \;] {
	set Cookie [string trim $Cookie]
	lassign [split $Cookie =] Name Value
	if {$Name eq $SessionCookie} {
	    set Session $Value
	    break
	}
    }
    if {![string length $Session]} {
	ns_returnredirect $Location
	return filter_return
    }
    if {![nsv_dict exists authn session $Session]} {
	ns_returnbadrequest "Invalid session"
	ns_log error "session does not exist: $Session"
	return filter_return
    }
    if {![nsv_dict exists authn session $Session username]} {
	ns_returnbadrequest "Invalid session"
	ns_log error "session has no user: $Session
	return filter_return
    }
    set Auth [ns_conn auth]
    ns_set update $Auth username [nsv_dict get authn session $Session username]
    ns_set update $Auth password ""
    ns_set update $Auth AuthMethod Session
    ns_set update $Auth session $Sesssion
    return filter_ok
}

proc authn:newSession {} {
    # 
    # Register as request proc at auth location
}

proc authn:getNewSessionId {} {

    set Count 6
    set Session ""
    while {[incr Count -1]} {
	set NewSession [ns_rand 2147483647]
	if {![nsv_dict exists authn session $NewSession]} {
	    set Session $NewSession
	    break
	}
    }
    if {![string length $Session]} {
	error "not able to get unique session identifier"
    }
    return $Session
}
