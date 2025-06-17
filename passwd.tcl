#
# License here
#

#
# modules/nsauthn/passwd.tcl
#

proc authn::passwd {Method URL User Password Remote CheckedURL {Config passwd} {Optional true}} {
    # Check user credentials against a passwd file.
    
    if {![matchURL $URL $CheckedURL]} {return UNAUTHORIZED}

    set Server [ns_info server]
    set ConfigSection ns/server/$Server/authn/passwd
    set LogLevel       [ns_config $ConfigSection loglevel debug]
    set LogCredentials [ns_config $ConfigSection logcredentials false]
    
    if {![string length $Password]} {unauthorized "empty password"}
    if {![string length $User]} {unauthorized "empty user"}
    
    set Hash [getHash $User $Config]

    if {![string length $Hash]} {unauthorized "user not found"}

    if {![checkpass $Password $Hash]} {unauthorized "invalid credentials"}

    # Note: this fails with: Warning: authorize script error: no connection
    #ns_set update [ns_conn auth] RemoteUser $User
    
    return -code [expr {$Optional ? "continue" : "break"}] OK
}

proc authn::checkpass {Password Hash} {
    # Notes:
    # - Only password hash algorithms available in Naviserver are supported
    # - Only phc-sf-spec is supported
    #   https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    #
    # - ns_crypt: unix DES, obsolete
    # - ns_crypto: argon2, not compatible with argon2 commandline tool
    #
    # tbd. check if workable
    # - $7$ - scrypt
    # - $8$ - pbkdf2

    # unix crypt(1)
    # - $1$ - md5crypt might be able to implement via ns_md
    #  maybe via ns_crypto
    # - $5$ - sha256crypt
    # - $6$ - sha512crypt

    # $id$version$parameter$salt$hashed$ .. version, parameter and last $ are optional
    set Parts [split [string trim $Hash \$] \$]

    if {[llength $Parts] == 1} {
	# unix DES
	set Salt [string range $Hash 0 1]
	return [expr {$Hash eq [ns_crypt $Password $Salt]}]
    }

    set Parts [lassign $Parts Id]

    if {[string match argon2* $Id]} {
	return [checkArgon2 $Password $Id {*}$Parts]
    }
    
    ns_log error "invalid or unsupport password hash: $Id"
    return false
}

proc authn::checkArgon2 {Password Id args} {
    # Hash Passwort against the parameters and hash of parts of a $Id
    # Argon2 passwd hash
    #
    # Note: Unfortunately the "argon2" package (Debian, Alpine)
    #   produces a different password hash then the Openssl library

    if {$Id ni {argon2i argon2d argon2id}} {
	invalidHash argon2 "invalid variant"
    }
    if {[llength $args] != 4} {
    	invalidHash argon2 "wrong number of components"
    }
    lassign $args Version Params Salt Hash
    if {$Version ne "v=19"} {
	invalidHash argon2 "invalid version"
    }
    set Params [split $Params ,]
    if {[llength $Params] != 3} {
	invalidHash argon2 "wrong number of parameters"
    }
    set ArgonArgs  [list -variant $Id -outlen 32]
    set ParamNames ""
    foreach Param $Params {
	lassign [split $Param =] Name Value
	if {![string length $Value]} {
	    invalidHash argon2 "empty parameter value"
	}
	append ParamNames $Name
	switch -exact $Name {
	    m {lappend ArgonArgs -memcost $Value}
	    t {lappend ArgonArgs -iter $Value}
	    p {lappend ArgonArgs -lanes $Value}
	    default {
		invalidHash argon2 "invalid parameter name"
	    }
	}
    }
    if {$ParamNames ne "mtp"} {
	invalidHash argon2 "invalid parameter order"
    }
    set PasswordHash \
	[B64encode [ns_crypto::argon2 -binary -encoding binary \
			-password $Password -salt [binary decode base64 $Salt] \
			{*}$ArgonArgs]]
    return [expr {$PasswordHash eq $Hash}]
}

proc authn::invalidHash {Name Message}  {
    ns_log error "invalid $Name hash: $Message"
    return -level 2 false
}

# Note: Implementation according to definition
#proc authn::B64encode String {
#    set PadLen [expr {(3 - ([string length $String]%3))%3}]
#    set Encoded [ns_base64encode -binary $String[string repeat \0 $PadLen]]
#    string range $Encoded 0 end-$PadLen
#}
#
# Note: simplified implementation found somewhere on the net
proc authn::B64encode String {
    string trimright [ns_base64encode -binary $String] =
}
