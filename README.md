CAS security filter [![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.apereo.cas/cas-server-security-filter/badge.svg?style=flat)](https://maven-badges.herokuapp.com/maven-central/org.apereo.cas/cas-server-security-filter)
====================


This project provides blunt generic Java Servlet filters suitable for patching-in-place Java CAS server and Java CAS client deployments vulnerable to certain request parameter based bad-CAS-protocol-input attacks.

## Build [![Build Status](https://api.travis-ci.org/apereo/cas-server-security-filter.png)](http://travis-ci.org/apereo/cas-server-security-filter)


ResponseHeadersEnforcementFilter for patching CAS client usages
----------------------------------------------------------------------

This is a Java Servlet Filter to be used to inject default security headers into the respose:
See [this guide](http://docs.spring.io/spring-security/site/docs/current/reference/html/headers.html)
for reference. It has no dependencies.

Configuration options
---------------------

This Filter is optionally configured via Filter `init-param` in `web.xml`.

In general the Filter is very persnickety about init-params, such that if you give it a configuration that the Filter is not totally sure it understands, it will fail Filter initialization. Note that all configuration knobs are turned off by default.

### enableCacheControl init-param
When `true`, will inject the following headers into the response for non-static resources:

```
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
```

### enableXContentTypeOptions init-param
When `true`, will inject the following headers into the response:

```
X-Content-Type-Options: nosniff
```

### enableStrictTransportSecurity init-param
When `true`, will inject the following headers into the response:

```
Strict-Transport-Security: max-age=15768000 ; includeSubDomains
```
### enableXFrameOptions init-param
When `true`, will inject the following headers into the response:

```
X-Frame-Options: DENY
```
### enableXSSProtection init-param
When `true`, will inject the following headers into the response:

```
X-XSS-Protection: 1; mode=block
```

RequestParameterPolicyEnforcementFilter for patching CAS client usages
----------------------------------------------------------------------

This is a Java Servlet Filter for use in fronting potentially bugged Java CAS Client usages.

It is optionally configurable as to what parameters it checks, what characters it forbids in those checked parameters, and whether it allows those checked parameters to be multi-valued.

It has no dependencies.

Configuration options
---------------------

This Filter is optionally configured via Filter `init-param` in `web.xml`.

In general the Filter is very persnickety about init-params, such that if you give it a configuration that the Filter is not totally sure it understands, it will fail Filter initialization.

### parametersToCheck init-param


The _optional_ init-param `parametersToCheck` is a whitespace-delimited set of the names of request parameters the Filter will check.

The special value `*` instructs the Filter to check all parameters, and is the default behavior.

### charactersToForbid init-param

The _optional_ init-param `charactersToForbid` is a whitespace-delimited set of the individual characters the Filter will forbid.

The special magic value of exactly `none` instructs the Filter not to forbid any characters. (This is useful for using the Filter to block multi-valued-ness of parameters without sniffing on any characters.)

If not present, the Filter will default to forbidding the characters `? # & %` .

### allowMultiValuedParameters init-param

The _optional_ init-param `allowMultiValuedParameters` indicates whether the Filter should allow multi-valued
parameters.

If present the value of this parameter must be exactly `true` or `false`, with `false` as the default.



Configuration Examples
----------------------

### The default configuration

```xml
<filter>
  <filter-name>requestParameterFilter</filter-name>
  <filter-class>org.apereo.cas.security.RequestParameterPolicyEnforcementFilter</filter-class>
</filter>
...
<filter-mapping>
  <filter-name>requestParameterFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

In this configuration, the Filter will scrutinize all request parameters, requiring that they not be multi-valued, and requiring that they not contain any of `% ? # &`.

### Allow multi-valued parameters

Multi-valued parameters are essential for supporting forms with multi-choice selectors where the form submission is legitimately represented as repeated parameter names with different values.

So, if you want to scrutinize the characters in all parameters, you might have to relax the requirement that those parameters not be multi-valued.

```xml
<filter>
  <filter-name>requestParameterFilter</filter-name>
  <filter-class>org.apereo.cas.security.RequestParameterPolicyEnforcementFilter</filter-class>
  <init-param>
    <param-name>allowMultiValuedParameters</param-name>
    <param-value>true</param-value>
  </init-param>
</filter>
...
<filter-mapping>
  <filter-name>requestParameterFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
 ```

### Restrictions suitable for fronting a CAS Client

If you're using this Filter for protection in front of a CAS client library usage, you might want to tighten it down to just checking the request parameters involved in the CAS protocol.

```xml
<filter>
  <filter-name>requestParameterFilter</filter-name>
  <filter-class>org.apereo.cas.security.RequestParameterPolicyEnforcementFilter</filter-class>
  <init-param>
    <param-name>parametersToCheck</param-name>
    <param-value>ticket SAMLArt pgtIou pgtId</param-value>
  </init-param>
</filter>
...
<filter-mapping>
  <filter-name>requestParameterFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

### Restrictions suitable for fronting a CAS Server

Likewise, you could use this Filter in front of a CAS Server to prevent unexpected multi-valued submissions of CAS protocol parameters.

```xml
<filter>
  <filter-name>requestParameterFilter</filter-name>
  <filter-class>org.apereo.cas.security.RequestParameterPolicyEnforcementFilter</filter-class>
  <init-param>
    <param-name>parametersToCheck</param-name>
    <param-value>ticket SAMLArt service renew gateway warn logoutUrl pgtUrl</param-value>
  </init-param>
  <init-param>
    <param-name>charactersToForbid</param-name>
    <param-value>none</param-value>
  </init-param>
</filter>
...
<filter-mapping>
  <filter-name>requestParameterFilter</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

This approach has the advantage of only blocking specific CAS protocol parameters, so that if you were to map the Filter in front of say the services management UI you can block unexpectedly multi-valued CAS protocol parameters without blocking submission of the services management edit screen where multiple user attributes are selected for release to a service (a legitimate case of a multi-valued attribute).

### An entirely novel configuration

So, a neat thing about this Filter is that it has nothing to do with CAS and it has no dependencies at all other than the Servlet API, so on that fateful day when you discover that some Java web application has some problem involving illicit submissions of the semicolon character in a request parameter named `query`, you can plop this Filter in front of it and get back to safety.  Doing so will almost certainly just work, since this Filter has no external dependencies whatsoever except on the Servlet API that had to be present for that Web Application to be a Java web app anyway.

```xml
 <filter>
   <filter-name>requestParameterFilter</filter-name>
   <filter-class>org.apereo.cas.security.RequestParameterPolicyEnforcementFilter</filter-class>
   <init-param>
     <param-name>parametersToCheck</param-name>
     <param-value>query</param-value>
   </init-param>
   <init-param>
     <param-name>charactersToForbid</param-name>
     <param-value>;</param-value>
   </init-param>
 </filter>
 ...
 <filter-mapping>
   <filter-name>requestParameterFilter</filter-name>
   <url-pattern>/*</url-pattern>
 </filter-mapping>
```
