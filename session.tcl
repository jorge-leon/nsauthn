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
	return filter_ok; # Don't try to authenticate with session at the auth location
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
	ns_log error "session has no user: $Session"
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
    set Form [ns_conn form]
    set Action [ns_set get $Form action ""]
    
    if {[string length $Session] && ([expired $Session] || $Action in {renew logout})} {
	destroySession $Session
	# Note: Should we rather create a new empty ns_set?
	set Headers [ns_conn outputheaders]
	set SessionCookie [ns_config ns/server/[ns_info server]/authn/session cookie nsauthn_session]
	set Path [ns_config ns/server/[ns_info server]/authn/session path /]
	ns_set put $Headers "Set-Cookie" "$SessionCookie=;  Max-Age=0; path=$Path"
	reauthenticate $Headers
	return filter_return
    }
    
    return filter_ok
}

proc authn::newSession {} {
    # request proc for auth location
    #
    # Create a session and set the session cookie for the authenticated user.
    # If there is already a session cookie set, destroy the session.

    set Auth [ns_conn auth]
    set Username [ns_set $Auth get username ""]
    set Scheme [ns_set $Auth get AuthMethod ""]
    set Headers [ns_conn outputheaders]

    # Note: is $AuthMethod case sensitive?
    if {![string length $Username] || $AuthMethod ne "Basic"} {
	ns_log error "auth method incorrect or username empty: `$Scheme', `$Username'"
	reauthenticate $Headers
	return filter_return
    }
    set Session [getSession]
    if {[string length $Session]} {
	destroySession $Session
    }
    set Session [getNewSessionId]
    nsv_dict set authn session $Session username $Username
    set Expiry [ns_config ns/server/[ns_info server]/authn/session expiry 3600]
    nsv_dict set authn session $Session expire [expr {[clock seconds]+$Seconds}]

    set SessionCookie [ns_config ns/server/[ns_info server]/authn/session cookie nsauthn_session]
    set Path [ns_config ns/server/[ns_info server]/authn/session path /]
    # Note: if we use a _Host- prefix we cannot use a path other then /
    ns_set put $Headers "Set-Cookie" "$SessionCookie=$Session; path=$Path; Secure; HttpOnly; SameSite=Strict"
    ns_return 200 text/plain "Session for $Username successfully created: $Session"
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

proc authn::getNewSessionId {} {

    set Count 6
    set Session ""
    while {[incr Count -1]} {
	set NewSession [ns_md5 string [ns_rand 2147483647]]
	if {![nsv_dict exists authn session $NewSession]} {
	    set Session $NewSession
	    break
	}
    }
    if {![string length $Session]} {
	error "unable to get unique session identifier"
    }
    return $Session
}

proc authn::reauthenticate Headers {
    set Realm [ns_config ns/server/[ns_info server]/authn/session realm nsauthn_session]
    ns_set put $Headers "WWW-Authenticate" "Basic realm=\"$Realm\", charset=\"UTF-8\""
    ns_respond -status 401 -type text/plain -headers $Headers -string "Authenticate to get a valid session"
}
