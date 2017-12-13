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
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
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
public final class AddResponseHeadersFilter extends AbstractSecurityFilter implements Filter {
    private static final Logger LOGGER = Logger.getLogger(AddResponseHeadersFilter.class.getName());

    private Map<String, String> headersMap = new LinkedHashMap<>();

    public AddResponseHeadersFilter() {
        FilterUtils.configureLogging(getLoggerHandlerClassName(), LOGGER);
    }

    public void setHeadersMap(final Map<String, String> headersMap) {
        this.headersMap = headersMap;
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
        while (initParamNames.hasMoreElements()) {
            final String paramName = initParamNames.nextElement().toString();
            final String paramValue = filterConfig.getInitParameter(paramName);
            this.headersMap.put(paramName, paramValue);
        }
    }

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                         final FilterChain filterChain) throws IOException, ServletException {
        try {
            if (servletResponse instanceof HttpServletResponse) {
                final HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
                for (final Map.Entry<String, String> entry : this.headersMap.entrySet()) {
                    LOGGER.fine("Adding parameter " + entry.getKey() + " with value " + entry.getValue());
                    httpServletResponse.addHeader(entry.getKey(), entry.getValue());
                }
            }
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, e);
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {
    }
}
