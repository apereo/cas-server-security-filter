/**
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
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
 * <pre>
 * Cache-Control: no-cache, no-store, max-age=0, must-revalidate
 * Pragma: no-cache
 * Expires: 0
 * X-Content-Type-Options: nosniff
 * Strict-Transport-Security: max-age=15768000 ; includeSubDomains
 * X-Frame-Options: DENY
 * X-XSS-Protection: 1; mode=block
 * </pre>
 *
 * @author Misagh Moayyed
 * @since 2.0.4
 */
public class ResponseHeadersEnforcementFilter extends AbstractSecurityFilter implements Filter {
    private static final Logger LOGGER = Logger.getLogger(ResponseHeadersEnforcementFilter.class.getName());

    private static final String INIT_PARAM_ENABLE_CACHE_CONTROL = "enableCacheControl";
    private static final String INIT_PARAM_ENABLE_XCONTENT_OPTIONS = "enableXContentTypeOptions";
    private static final String INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY = "enableStrictTransportSecurity";

    private static final String INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS = "enableXFrameOptions";
    private static final String INIT_PARAM_STRICT_XFRAME_OPTIONS = "XFrameOptions";

    private static final String INIT_PARAM_ENABLE_XSS_PROTECTION = "enableXSSProtection";
    private static final String INIT_PARAM_XSS_PROTECTION = "XSSProtection";

    private static final String INIT_PARAM_CONTENT_SECURITY_POLICY = "contentSecurityPolicy";

    private boolean enableCacheControl;

    private boolean enableXContentTypeOptions;
    private String xContentTypeOptionsHeader = "nosniff";

    // allow for 6 months; value is in seconds
    private boolean enableStrictTransportSecurity;
    private String strictTransportSecurityHeader = "max-age=15768000 ; includeSubDomains";

    private boolean enableXFrameOptions;
    private String XFrameOptions = "DENY";

    private boolean enableXSSProtection;
    private String XSSProtection = "1; mode=block";

    private String contentSecurityPolicy;

    public void setXSSProtection(final String XSSProtection) {
        this.XSSProtection = XSSProtection;
    }

    public void setXFrameOptions(final String XFrameOptions) {
        this.XFrameOptions = XFrameOptions;
    }

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

    public void setContentSecurityPolicy(final String contentSecurityPolicy) {
        this.contentSecurityPolicy = contentSecurityPolicy;
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
            this.XFrameOptions = filterConfig.getInitParameter(INIT_PARAM_STRICT_XFRAME_OPTIONS);
            if (this.XFrameOptions == null || this.XFrameOptions.isEmpty()) {
                this.XFrameOptions = "DENY";
            }
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS
                + "] with value [" + enableXFrameOptions + "]", e));
        }

        try {
            this.enableXSSProtection = FilterUtils.parseStringToBooleanDefaultingToFalse(enableXSSProtection);
            this.XSSProtection = filterConfig.getInitParameter(INIT_PARAM_XSS_PROTECTION);
            if (this.XSSProtection == null || this.XSSProtection.isEmpty()) {
                this.XSSProtection = "1; mode=block";
            }
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing parameter [" + INIT_PARAM_ENABLE_XSS_PROTECTION
                + "] with value [" + enableXSSProtection + "]", e));
        }

        this.contentSecurityPolicy = filterConfig.getInitParameter(INIT_PARAM_CONTENT_SECURITY_POLICY);
    }

    /**
     * Examines the Filter init parameter names and throws ServletException if they contain an unrecognized
     * init parameter name.
     * <p>
     * This is a stateless static method.
     * <p>
     * This method is an implementation detail and is not exposed API.
     * This method is only non-private to allow JUnit testing.
     *
     * @param initParamNames init param names, in practice as read from the FilterConfig.
     */
    static void throwIfUnrecognizedParamName(final Enumeration initParamNames) {
        final Set<String> recognizedParameterNames = new HashSet<String>();
        recognizedParameterNames.add(INIT_PARAM_ENABLE_CACHE_CONTROL);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_XCONTENT_OPTIONS);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_STRICT_TRANSPORT_SECURITY);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_STRICT_XFRAME_OPTIONS);
        recognizedParameterNames.add(INIT_PARAM_STRICT_XFRAME_OPTIONS);
        recognizedParameterNames.add(INIT_PARAM_CONTENT_SECURITY_POLICY);
        recognizedParameterNames.add(LOGGER_HANDLER_CLASS_NAME);
        recognizedParameterNames.add(INIT_PARAM_ENABLE_XSS_PROTECTION);
        recognizedParameterNames.add(INIT_PARAM_XSS_PROTECTION);

        while (initParamNames.hasMoreElements()) {
            final String initParamName = (String) initParamNames.nextElement();
            if (!recognizedParameterNames.contains(initParamName)) {
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

                decideInsertCacheControlHeader(httpServletResponse, httpServletRequest);
                decideInsertStrictTransportSecurityHeader(httpServletResponse, httpServletRequest);
                decideInsertXContentTypeOptionsHeader(httpServletResponse, httpServletRequest);
                decideInsertXFrameOptionsHeader(httpServletResponse, httpServletRequest);
                decideInsertXSSProtectionHeader(httpServletResponse, httpServletRequest);
                decideInsertContentSecurityPolicyHeader(httpServletResponse, httpServletRequest);
            }
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException(getClass().getSimpleName()
                + " is blocking this request. Examine the cause in this stack trace to understand why.", e));
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    protected void decideInsertContentSecurityPolicyHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (this.contentSecurityPolicy == null) {
            return;
        }
        insertContentSecurityPolicyHeader(httpServletResponse, httpServletRequest, this.contentSecurityPolicy);
    }

    protected void insertContentSecurityPolicyHeader(final HttpServletResponse httpServletResponse,
                                                     final HttpServletRequest httpServletRequest,
                                                     final String contentSecurityPolicy) {
        final String uri = httpServletRequest.getRequestURI();
        httpServletResponse.addHeader("Content-Security-Policy", contentSecurityPolicy);
        LOGGER.fine("Adding Content-Security-Policy response header " + contentSecurityPolicy + " for " + uri);
    }

    protected void decideInsertXSSProtectionHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableXSSProtection) {
            return;
        }
        insertXSSProtectionHeader(httpServletResponse, httpServletRequest, this.XSSProtection);
    }

    protected void insertXSSProtectionHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest,
                                             final String XSSProtection) {
        final String uri = httpServletRequest.getRequestURI();
        httpServletResponse.addHeader("X-XSS-Protection", XSSProtection);
        LOGGER.fine("Adding X-XSS Protection " + XSSProtection + " response headers for " + uri);
    }

    protected void decideInsertXFrameOptionsHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableXFrameOptions) {
            return;
        }
        insertXFrameOptionsHeader(httpServletResponse, httpServletRequest, this.XFrameOptions);
    }

    protected void insertXFrameOptionsHeader(final HttpServletResponse httpServletResponse,
                                             final HttpServletRequest httpServletRequest,
                                             final String xFrameOptions) {
        final String uri = httpServletRequest.getRequestURI();
        httpServletResponse.addHeader("X-Frame-Options", xFrameOptions);
        LOGGER.fine("Adding X-Frame Options " + xFrameOptions + " response headers for [{}]" + uri);
    }

    protected void decideInsertXContentTypeOptionsHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableXContentTypeOptions) {
            return;
        }
        insertXContentTypeOptionsHeader(httpServletResponse, httpServletRequest, this.xContentTypeOptionsHeader);
    }

    protected void insertXContentTypeOptionsHeader(final HttpServletResponse httpServletResponse,
                                                   final HttpServletRequest httpServletRequest,
                                                   final String xContentTypeOptionsHeader) {
        final String uri = httpServletRequest.getRequestURI();
        httpServletResponse.addHeader("X-Content-Type-Options", xContentTypeOptionsHeader);
        LOGGER.fine("Adding X-Content Type response headers " + xContentTypeOptionsHeader + " for " + uri);
    }

    protected void decideInsertCacheControlHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableCacheControl) {
            return;
        }
        insertCacheControlHeader(httpServletResponse, httpServletRequest);
    }

    protected void insertCacheControlHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {

        final String uri = httpServletRequest.getRequestURI();
        if (!uri.endsWith(".css")
            && !uri.endsWith(".js")
            && !uri.endsWith(".png")
            && !uri.endsWith(".txt")
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

    protected void decideInsertStrictTransportSecurityHeader(final HttpServletResponse httpServletResponse, final HttpServletRequest httpServletRequest) {
        if (!this.enableStrictTransportSecurity) {
            return;
        }
        insertStrictTransportSecurityHeader(httpServletResponse, httpServletRequest, this.strictTransportSecurityHeader);
    }

    protected void insertStrictTransportSecurityHeader(final HttpServletResponse httpServletResponse,
                                                       final HttpServletRequest httpServletRequest,
                                                       final String strictTransportSecurityHeader) {
        if (httpServletRequest.isSecure()) {
            final String uri = httpServletRequest.getRequestURI();

            httpServletResponse.addHeader("Strict-Transport-Security", strictTransportSecurityHeader);
            LOGGER.fine("Adding HSTS response headers for " + uri);
        }
    }

    @Override
    public void destroy() {
    }
}
