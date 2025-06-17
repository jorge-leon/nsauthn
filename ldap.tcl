#
# License here
#

#
# modules/nsauthn/ldap.tcl
#

proc authn::ldap {Method URL User Password Remote CheckedURL {Config default} {Optional true}} {
    # Check user credentials against ldap
    
    if {![matchURL $URL $CheckedURL]} {return UNAUTHORIZED}

    set Server [ns_info server]
    set ConfigSection ns/server/$Server/authn/ldap
    set LogLevel       [ns_config $ConfigSection loglevel debug]
    set LogCredentials [ns_config $ConfigSection logcredentials false]
    
    if {![string length $Password]} {unauthorized "empty password"}
    if {![string length $User]} {unauthorized "empty user"}

    if {![ldapBind $Config $User $Password]} {unauthorized "invalid credentials"}

    # Note: this fails with: Warning: authorize script error: no connection
    #ns_set update [ns_conn auth] RemoteUser $User
    
    return -code [expr {$Optional ? "continue" : "break"}] OK
}

proc authn::ldapBind {Config Username Password} {

    set Server [ns_info server]
    set ConfigSection ns/server/$Server/authn/ldap
    set LogLevel       [ns_config $ConfigSection loglevel debug]
    append ConfigSection / $Config
    set Pool [ns_config $ConfigSection pool ""]
    if {![string length $Pool]} {
	error "no pool configured: $ConfigSection"
    }
    set Base [ns_config $ConfigSection base ""]
    if {![string length $Base]} {
	error "no base configured: $ConfigSection"
    }
    set Filter [ns_config $ConfigSection filter ""]
    if {![string length $Filter]} {
	error "no filter configured: $ConfigSection"
    }
    set Scope [ns_config $ConfigSection scope subtree]
    set Handle [ns_ldap gethandle $Pool]

    set Filter [subst -nocommands -nobackslashes $Filter]
    set DNs [ns_ldap search $Handle -scope $Scope -names true $Base $Filter]

    set Rest [lassign $DNs DN]

    if {[llength $Rest]} {
	ns_ldap releasehandle $Handle
	error "more then one match $Pool: $Filter"
    }
    if {![string length $DN]} {
	ns_ldap releasehandle $Handle
	ns_log $LogLevel "no match for user $Username in ldap pool $Pool with filter $Filter"
	return false
    }
    set Authenticated false
    try {
	ns_ldap bind $Handle $DN $Password
	set Authenticated true
    } on error {Msg Err} {
	ns_log $LogLevel $Msg
    }

    # Note: Username mapping here is only for demo purposes. It relies
    # on the pool user to be able to read the given attribute, which
    # is not what we normaly want.
    
    set UserAttribute [ns_config $ConfigSection userattribute ""]
    if {[string length $UserAttribute]} {
	set Result [ns_ldap search $Handle -scope base $DN (objectClass=*) $UserAttribute]
	ns_log notice "$Result"
	# Note: search guarantees single result, save race conditions in the directory.
	set Attributes [dict create {*}[lindex $Result 0]]
	if {[dict exists $Attributes $UserAttribute]} {
	    set Values [dict get $Attributes $UserAttribute]
	    if {[llength $Values]>1} {
		error "nsauth::ldap $UserAttribute is multi-valued: $Values"
	    }
	    set User [lindex $Values 0]
	    ns_log $LogLevel "nsauth::ldap mapping username $Username to $UserAttribute: $User"
	    # Note: this fails with: Warning: authorize script error: no connection
	    #ns_set update [ns_conn auth] Username $User
	} else {
	    error "nsauth::ldap user attribute $UserAttribute does not exist or is empty: $DN"
	}
    }
    
    ns_ldap releasehandle $Handle
    return $Authenticated
}
