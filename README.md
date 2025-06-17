# Basic Authentication Module for Naviserver

*Note*: This module is compatible with Naviserver source as of 17th of
June 2025 or later and with Tcl 8.6 and probably later.

## Overview

*nsauthn* is a pure Tcl module leveraging the newly introduced hooks
into the 'auth' processing stage of Naviserver which provides for HTTP
Basic Authentication.


*nsauthn* can be configured to use one of the following user database
backends:

- passwd files with (obsolete) Unix DES and state-of-the art argon2i
  password hashes.

- LDAP/AD directories.


## Installation Instructions

`make install` will install *nsauthn* to the module directory of a
Naviserver created from an unmodified source tree.

To use a different location set `NAVISERVER` to the respective directory prefix.


## Configuration

User databases are configured in `ns/authn/`*`backend type`*/*`name`* configuration
sections.

Backend types:

`passwd`
: .. password file.

`ldap`
: .. LDAP authentication using the /nsldap/ module.

The backends can be used in one or more `ns/server`
configurations. They are set up in `nsauthn/`*`backend type`*
subsections.

The following is a server configuration template:

```tcl
    ns_section ns/server/<server>/modules {
	ns_param     nsauthn            tcl
	}

	ns_section ns/server/<server>/authn/<type> {
    ns_param     map                {<pattern> <backend> <success>}
	ns_param     loglevel           debug
    ns_param     logcredentials     false
}
```
`loglevel` and `logcredentials` are optional, the values shown are
their defaults.

Variables:

`<server>`
: .. server name.

`<type>`
: .. backend type.

`<pattern>`
: .. URL pattern: /path* is matched with `string match`,
  `/path/` matches exact on `/path`, `/path/` otherwise does a
  `string match` on `/path/*`.

`<backend>`
: .. backend instance (of `<type>`) to query for user  credentials.

`<success>`
: .. `optional`, `required` or omitted.  If `optional`
  on failure to authenticate the next auth handler in the chain is
  queried.

One or more `map` configurations can be specified.  Upon
initialization a corresponding handler is registered in the auth
chain of the respective server for each of them in order of appearance.


### Passwd Backend Configuration

The following is a passwd backend configuration template.

```tcl
ns_section ns/authn/passwd/<backend> {
    ns_param     passwd            <path>
}
```

Variables:

`<backend>`
: .. backend instance name.

`<path>`
: .. relative path to passwd file with respect to the `conf` sub
  directory within the server home directory.


### Passwd Files

On first use of a passwd backend the configured passwd file is read
and the user credentials are cached.  The registered auth procedure
re-reads the passwd file if it is changed.

When reading the passwd file each line is split into colon (`:`)
separated fields.  The first field is taken as username, the second
field as password hash. Any other fields are ignored.

Password hashes are processed according to the
[phc-sf-spec](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md).

The support hashes are Unix DES and Argon2.  They can be produces with
the Naviserver builtins `ns_crypt` and `ns_crypto`.

*Note*: `ns_crypto` is based on OpenSSL and produces Argon2 hashes
which are not compatible with the `mkpasswd` utility which is based on
crypt(3).


### LDAP Backend Configuration

The following is a ldap backend configuration template.

```tcl
ns_section ns/authn/ldap/<backend> {
    ns_param     pool               <pool>
    ns_param     base               <basedn>
    ns_param     filter             <filter>
    ns_param     scope              <scope>
    ns_param     userattribute      <uat>
}
```

Variables:

`<backend>`
: .. backend instance name.

`<pool>`
: .. /nsldap/ pool to use.

`<basedn>`
: .. Base DN to use for user searches.

`<filter>`
: .. LDAP filter to use for user searches. The variable
  `$Username` will be replaced with the username string send by the
  web browser in the `Authentication` header.

`<scope>`
: .. optional. LDAP search scope, default `subtree`.

`<uat>`
: .. optional, not working. Meant to map the Username from the
  `Authentication` header with the value from an LDAP attribute in the
  user entry.

## `nsldap`

For me to work I had to do the following:

- Compile `nsldap` with `LDAPV3` defined.
- Set `maxidle` to `0` in the `nsldap` pool configuration, otherwise
  initialization fails.

Use a low privileged user for the pool. Authentication is done via a
rebind, however `nsldap` does not allow any operation within the
rebind (which is a good thing(tm)).


## Motivation

Until the implementation of `ns_register_auth` in Naviserver the only
way to extend HTTP Authentication was by creating a module written in C.

The canonical (only?) module was `nsperm`, which acts for
authentication and access control (authorization) at the same
time. `nsperm` has some limitations:

- passwd file and access control configuration files are in fixed
  locations.
- Only one set of them can be used for a Naviserver instance
- The password hash is obsolete and unsecure
- Naviserver has to be restarted when credentials are changed (or
  `nscp` must be enabled).
- Access to the host is required for credential changes.

`nsauthn` addresses some of these issues, while having a much narrower
scope.  No group, ACL or access control via client IP is implemented
in the believe, that this can be added by composition via the auth
chain.


## ToDo

- SQL based backends.
- Sessions.
- Password hash generation tools
- IP based access control.
- More password hashes.


## Authors

- Georg Lehner (<jorge@magma-soft.at>)
