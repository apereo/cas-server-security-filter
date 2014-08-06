# CAS server security filter

This project is a J2E filter to be installed in all CAS servers for version < 4.1.
It must be installed as the first filter in the CAS server (*web.xml* file):

    <filter>
      <filter-name>securityFilter</filter-name>
      <filter-class>org.jasig.cas.security.SecurityFilter</filter-class>
    </filter>
    <filter-mapping>
      <filter-name>securityFilter</filter-name>
      <url-pattern>/*</url-pattern>
    </filter-mapping>

It protects against HTTP attacks by checking than request parameters do not appear more than once in the url.

It could be used in other web applications with the same security need.

## Build [![Build Status](https://api.travis-ci.org/Jasig/cas-server-security-filter.png)](http://travis-ci.org/Jasig/cas-server-security-filter)
