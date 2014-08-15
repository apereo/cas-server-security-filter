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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests the {@link SecurityFilter}.
 *
 * @author Jerome Leleu
 * @since 1.0.0
 */
public final class SecurityFilterTests {

    private final static String KEY = "key";
    private final static String[] SINGLE_VALUE = new String[] { "value" };
    private final static String[] MULTIPLE_VALUES = new String[] { "value2", "value2" };
    private final static String URL = "http://www.apereo.org";

    private FilterConfig filterConfig;

    private ServletContext servletContext;
    
    private HttpServletRequest request;
    
    private HttpServletResponse response;
    
    private FilterChain chain;
    
    private SecurityFilter filter;

    private Map<String, String[]> parameters;
    
    @Before
    public void setUp() throws ServletException {

        servletContext = mock(ServletContext.class);
        filterConfig = mock(FilterConfig.class);
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        request = mock(HttpServletRequest.class);
        parameters = new HashMap<String, String[]>();
        when(request.getParameterMap()).thenReturn(parameters);
        when(request.getRequestURI()).thenReturn(URL);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        filter = new SecurityFilter();

        filter.init(filterConfig);
    }

    /**
     * No invalid request, no exception is thrown: the test passes.
     *
     * @throws ServletException 
     * @throws IOException 
     */
    @Test
    public void testUrlOk() throws IOException, ServletException {
        parameters.put(KEY, SINGLE_VALUE);
        filter.doFilter(request, response, chain);
    }

    /**
     * A parameter appears twice: an {@link IllegalArgumentException} is expected.
     *
     * @throws ServletException 
     * @throws IOException 
     */
    @Test
    public void testParameterTwiceValues() throws IOException, ServletException {
        parameters.put(KEY, MULTIPLE_VALUES);
        try {
            filter.doFilter(request, response, chain);
            fail("should fail");
        } catch (final IllegalArgumentException e) {
            assertEquals("'" + KEY + "' parameter appears more than once for url: " + URL, e.getMessage());
        }
    }
}
