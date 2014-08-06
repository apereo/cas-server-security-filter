/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
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
package org.jasig.cas.security;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This security filter is meant to be used within the CAS server, but could be used in other web applications.
 * Its role is to "protect against HTTP attacks".
 *
 * It checks that:
 * - any request parameter does not appear more than once in the url. Otherwise, an {@link IllegalArgumentException}
 *   is thrown. 
 *
 * @author Jerome Leleu
 * @since 1.0.0
 */
public class SecurityFilter implements Filter {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        logger.debug("Call security filter for: {}", httpRequest.getRequestURI());
        
        checkParameterOnlyAppearOnce(httpRequest);

        chain.doFilter(request, response);
    }

    @SuppressWarnings("unchecked")
    protected void checkParameterOnlyAppearOnce(final HttpServletRequest request) {
        final Map<String, String[]> parameters = request.getParameterMap();
        if (parameters != null) {
            final Set<String> keys = parameters.keySet();
            if (keys != null) {
                for (final String key : keys) {
                    final String[] values = parameters.get(key);
                    if (values != null && values.length > 1) {
                        final String message = "'" + key + "' parameter appears more than once for url: "
                                + request.getRequestURI();
                        logger.error(message);
                        throw new IllegalArgumentException(message);
                    }
                }
            }
        }        
    }

    @Override
    public void destroy() {
    }
}
