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

It protects against HTTP attacks by checking that request parameters do not appear more than once in the url.

For CAS servers older than the 4.0 version, the management webapp is embedded in the CAS server itself, so this filter may cause problems when editing services.  
In that case, the filter mapping must be restrained to the CAS server urls:

    <filter-mapping>
      <filter-name>securityFilter</filter-name>
      <url-pattern>/login</url-pattern>
    </filter-mapping>
    <filter-mapping>
      <filter-name>securityFilter</filter-name>
      <url-pattern>/logout</url-pattern>
    </filter-mapping>
    <filter-mapping>
      <filter-name>securityFilter</filter-name>
      <url-pattern>/validate</url-pattern>
    </filter-mapping>
    <filter-mapping>
      <filter-name>securityFilter</filter-name>
      <url-pattern>/samlValidate</url-pattern>
    </filter-mapping>
    <filter-mapping>
      <filter-name>securityFilter</filter-name>
      <url-pattern>/serviceValidate</url-pattern>
    </filter-mapping>
    <filter-mapping>
      <filter-name>securityFilter</filter-name>
      <url-pattern>/proxyValidate</url-pattern>
    </filter-mapping>
    <filter-mapping>
      <filter-name>securityFilter</filter-name>
      <url-pattern>/proxy</url-pattern>
    </filter-mapping>

It could be used in other web applications with the same security need.

## Build [![Build Status](https://api.travis-ci.org/Jasig/cas-server-security-filter.png)](http://travis-ci.org/Jasig/cas-server-security-filter)
