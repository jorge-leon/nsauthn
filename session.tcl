#
# License here
#

#
# modules/nsauthn/sesion.tcl
#

proc authn::session {Stage args} {
    # preauth filter for session authenticated URL's
    #
    # - If a session cookie is present and valid pass to the next filter
    #   in chain (or auth, then postauth then to the request handler.
    # - If there is no session cookie redirect to the registered auth location.
    # - Else signal a respective error.
    #
    # Checks if session cookie is present and valid.

    if {$Stage ne "preauth"} {
	error "invalid configuration, called in stage: $Stage"
    }
    set Location [ns_config ns/server/[ns_info server]/authn/session authlocation ""]
    if {![string length $Location]} {
	error "invalid configuration, no auth redirect location configured"
    }
    set URL [ns_conn url]
    if {$Location eq $URL} {
	return filter_return; # Don't try to authenticate with session at the auth location
    }

    set Session [getSession]
    if {![string length $Session]} {
	ns_returnredirect $Location; # Redirect to auth location to obtain a session
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
    if {[expired $Session]} {
	ns_returnredirect $Location; # Redirect to auth location to renew current session
	return filter_return
    }
    
    set Auth [ns_conn auth]
    ns_set update $Auth username [nsv_dict get authn session $Session username]
    ns_set update $Auth password ""
    ns_set update $Auth AuthMethod Session
    ns_set update $Auth session $Sesssion
    return filter_ok
}

proc auth::checkSession {} {
    # preauth filter for auth location
    #
    # - If no or a valid session cookie is found pass to next filter (or auth, then postauth)
    # - If an expired session cookie is found delete the session, the session cookie and reauthenticate

    set Session [getSession]
    if {[string length $Session] && [expired $Session]} {
	destroySession $Session
	# Note: Should we rather create a new empty ns_set?
	set Headers [ns_conn outputheaders]
	set SessionCookie [ns_config ns/server/[ns_info server]/authn/session cookie nsauthn_session]
	set Path [ns_config ns/server/[ns_info server]/authn/session path /]
	ns_set put $Headers "Set-Cookie" "$SessionCookie=;  Max-Age=0; path=$Path"
	set Realm [ns_config ns/server/[ns_info server]/authn/session realm nsauthn_session]
	ns_set put $Headers "WWW-Authenticate" "Basic realm=\"$Realm\", charset=\"UTF-8\""
	ns_respond -status 401 -type text/plain -headers $Headers -string
	return filter_return
    }
    
    return filter_ok
}

proc authn::newSession {} {
    # request proc for auth location
    #
    # - If no session cookie is present, or there is a valid one for
    #   the currently authenticated user create or renew the session
    #   and set a session cookie.
    # - Otherwise signal the respective error
    #

    set Auth [ns_conn auth]
    
}

proc authn::getSession {} {
    # Return session id from cookie or empty string
    
    set SessionCookie [ns_config ns/server/[ns_info server]/authn/session cookie nsauthn_session]
    set Headers [ns_conn headers]
    set Cookies [concat {*}[ns_set get -all -nocase $Headers Cookie]]
    foreach Cookie [split $Cookies \;] {
	set Cookie [string trim $Cookie]
	lassign [split $Cookie =] Name Value
	if {$Name eq $SessionCookie} {return $Value}
    }
    return ""
}

proc authn::expired Session {
    if {![nsv_dict exists authn session $Session expiry]} {
	error "session does not have expiry"
    }
    return [expr {[nsv_dict get authn session $Session expiry] > [clock seconds]}]
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
