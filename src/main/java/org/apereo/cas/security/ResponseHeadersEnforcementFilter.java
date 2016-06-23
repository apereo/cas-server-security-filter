/**
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apereo.cas.security;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Allows users to easily inject the default security headers to assist in protecting the application.
 * The default for is to include the following headers:
 *
 * <pre>
 Cache-Control: no-cache, no-store, max-age=0, must-revalidate
 Pragma: no-cache
 Expires: 0
 X-Content-Type-Options: nosniff
 Strict-Transport-Security: max-age=15768000 ; includeSubDomains
 X-Frame-Options: DENY
 X-XSS-Protection: 1; mode=block
 * </pre>
 * @author Misagh Moayyed
 * @since 2.0.4
 */
public final class ResponseHeadersEnforcementFilter extends AbstractSecurityFilter implements Filter {
    private static final Logger LOGGER = Logger.getLogger(ResponseHeadersEnforcementFilter.class.getName());

    private static final String INIT_PARAM_ENABLE_CACHE_CONTROL = "enableCacheControl";
    private static final String INIT_PARAM_ENABLE_XCONTENT_OPTIONS = "enableXContentTypeOptions";
    private static final String INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY = "enableStrictTransportSecurity";
    private static final String INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS = "enableXFrameOptions";
    private static final String INIT_PARAM_ENABLE_XSS_PROTECTION = "enableXSSProtection";

    private boolean enableCacheControl;
    private boolean enableXContentTypeOptions;
    private boolean enableStrictTransportSecurity;
    private boolean enableXFrameOptions;
    private boolean enableXSSProtection;

    public void setEnableStrictTransportSecurity(final boolean enableStrictTransportSecurity) {
        this.enableStrictTransportSecurity = enableStrictTransportSecurity;
    }

    public void setEnableCacheControl(final boolean enableCacheControl) {
        this.enableCacheControl = enableCacheControl;
    }

    public void setEnableXContentTypeOptions(final boolean enableXContentTypeOptions) {
        this.enableXContentTypeOptions = enableXContentTypeOptions;
    }


    public void setEnableXFrameOptions(final boolean enableXFrameOptions) {
        this.enableXFrameOptions = enableXFrameOptions;
    }

    public void setEnableXSSProtection(final boolean enableXSSProtection) {
        this.enableXSSProtection = enableXSSProtection;
    }

    public ResponseHeadersEnforcementFilter() {
        FilterUtils.configureLogging(getLoggerHandlerClassName(), LOGGER);
    }

    @Override
    public void setLoggerHandlerClassName(final String loggerHandlerClassName) {
        super.setLoggerHandlerClassName(loggerHandlerClassName);
        FilterUtils.configureLogging(getLoggerHandlerClassName(), LOGGER);
    }
    
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        FilterUtils.configureLogging(getLoggerHandlerClassName(), LOGGER);

        final Enumeration initParamNames = filterConfig.getInitParameterNames();
        throwIfUnrecognizedParamName(initParamNames);


        final String enableCacheControl = filterConfig.getInitParameter(INIT_PARAM_ENABLE_CACHE_CONTROL);
        final String enableXContentTypeOptions = filterConfig.getInitParameter(INIT_PARAM_ENABLE_XCONTENT_OPTIONS);
        final String enableStrictTransportSecurity = filterConfig.getInitParameter(INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY);
        final String enableXFrameOptions = filterConfig.getInitParameter(INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS);
        final String enableXSSProtection = filterConfig.getInitParameter(INIT_PARAM_ENABLE_XSS_PROTECTION);


        try {
            this.enableCacheControl = FilterUtils.parseStringToBooleanDefaultingToFalse(enableCacheControl);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_CACHE_CONTROL
                    + "] with value [" + enableCacheControl + "]", e));
        }


        try {
            this.enableXContentTypeOptions = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXContentTypeOptions);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_XCONTENT_OPTIONS
                    + "] with value [" + enableXContentTypeOptions + "]", e));
        }

        try {
            this.enableStrictTransportSecurity = FilterUtils.parseStringToBooleanDefaultingToFalse(enableStrictTransportSecurity);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY
                    + "] with value [" + enableStrictTransportSecurity + "]", e));
        }

        try {
            this.enableXFrameOptions = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXFrameOptions);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS
                    + "] with value [" + enableXFrameOptions + "]", e));
        }

        try {
            this.enableXSSProtection = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXSSProtection);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_XSS_PROTECTION
                    + "] with value [" + enableXSSProtection + "]", e));
        }
    }

    /**
     * Examines the Filter init parameter names and throws ServletException if they contain an unrecognized
     * init parameter name.
     *
     * This is a stateless static method.
     *
     * This method is an implementation detail and is not exposed API.
     * This method is only non-private to allow JUnit testing.
     *
     * @param initParamNames init param names, in practice as read from the FilterConfig.
     * @throws ServletException if unrecognized parameter name is present
     */
    static void throwIfUnrecognizedParamName(final Enumeration initParamNames) throws ServletException {
        final Set<String> recognizedParameterNames = new HashSet<String>();
        recognizedParameterNames.add(INIT_PARAM_ENABLE_CACHE_CONTROL);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_XCONTENT_OPTIONS);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS);
        recognizedParameterNames.add(LOGGER_HANDLER_CLASS_NAME);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_XSS_PROTECTION);

        while (initParamNames.hasMoreElements()) {
            final String initParamName = (String) initParamNames.nextElement();
            if (! recognizedParameterNames.contains(initParamName)) {
                FilterUtils.logException(LOGGER, new ServletException("Unrecognized init parameter [" + initParamName + "].  Failing safe.  Typo" +
                        " in the web.xml configuration? " +
                        " Misunderstanding about the configuration "
                        + RequestParameterPolicyEnforcementFilter.class.getSimpleName() + " expects?"));
            }
        }
    }

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                         final FilterChain filterChain) throws IOException, ServletException {

        try {
            if (servletResponse instanceof HttpServletResponse) {
                final HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
                final HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
                final String uri = httpServletRequest.getRequestURI();

                if (this.enableCacheControl) {

                    if (!uri.endsWith(".css")
                            && !uri.endsWith(".js")
                            && !uri.endsWith(".png")
                            && !uri.endsWith(".jpg")
                            && !uri.endsWith(".ico")
                            && !uri.endsWith(".jpeg")
                            && !uri.endsWith(".bmp")
                            && !uri.endsWith(".gif")) {
                        httpServletResponse.addHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
                        httpServletResponse.addHeader("Pragma", "no-cache");
                        httpServletResponse.addIntHeader("Expires", 0);
                        LOGGER.fine("Adding Cache Control response headers for " + uri);
                    }
                }

                if (this.enableStrictTransportSecurity && servletRequest.isSecure()) {


                    //allow for 6 months; value is in seconds
                    httpServletResponse.addHeader("Strict-Transport-Security", "max-age=15768000 ; includeSubDomains");
                    LOGGER.fine("Adding HSTS response headers for " + uri);
                }

                if (this.enableXContentTypeOptions) {
                    httpServletResponse.addHeader("X-Content-Type-Options", "nosniff");
                    LOGGER.fine("Adding X-Content Type response headers for " + uri);
                }

                if (this.enableXFrameOptions) {
                    httpServletResponse.addHeader("X-Frame-Options", "DENY");
                    LOGGER.fine("Adding X-Frame Options response headers for " + uri);
                }

                if (this.enableXSSProtection) {
                    httpServletResponse.addHeader("X-XSS-Protection", "1; mode=block");
                    LOGGER.fine("Adding X-XSS Protection response headers for " + uri);
                }

            }
        } catch (final Exception e ) {
            FilterUtils.logException(LOGGER, new ServletException(getClass().getSimpleName() 
                    + " is blocking this request. Examine the cause in" +
                    " this stack trace to understand why.", e));
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {}
}
