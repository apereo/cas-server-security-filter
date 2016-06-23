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

import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Utility classes.
 *
 * @author Misagh Moayyed
 * @since 2.1
 */
public final class FilterUtils {
    private static final Logger LOGGER = Logger.getLogger(FilterUtils.class.getName());

    public static boolean throwOnErrors;

    private FilterUtils() {
    }

    public static void setThrowOnErrors(final boolean throwOnErrors) {
        FilterUtils.throwOnErrors = throwOnErrors;
    }

    /**
     * Parse a String to a boolean.
     * <p>
     * "true" : true
     * "false" : false
     * null : false
     * Anything else : logException(IllegalArgumentException).
     * <p>
     * This is a stateless static method.
     * <p>
     * This method is an implementation detail and is not exposed API.
     * This method is only non-private to allow JUnit testing.
     *
     * @param stringToParse a String to parse to a boolean as specified
     * @return true or false
     * @throws IllegalArgumentException if the String is not true, false, or null.
     */
    public static boolean parseStringToBooleanDefaultingToFalse(final String stringToParse) {

        if ("true".equals(stringToParse)) {
            return true;
        } else if ("false".equals(stringToParse)) {
            return false;
        } else if (null == stringToParse) {
            return false;
        }

        logException(LOGGER, new IllegalArgumentException("String [" + stringToParse +
                "] could not parse to a boolean because it was not precisely 'true' or 'false'."));
        return false;
    }

    private static Handler loadLoggerHandlerByClassName(final String loggerHandlerClassName) {
        try {
            if (loggerHandlerClassName == null) {
                return null;
            }

            final ClassLoader classLoader = RequestParameterPolicyEnforcementFilter.class.getClassLoader();
            final Class loggerHandlerClass = classLoader.loadClass(loggerHandlerClassName);
            if (loggerHandlerClass != null) {
                return (Handler) loggerHandlerClass.newInstance();
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, e.getMessage(), e);
        }
        return null;
    }

    public static void configureLogging(final Handler handler, final Logger logger) {
        for (final Handler h : logger.getHandlers()) {
            logger.removeHandler(h);
        }
        logger.setUseParentHandlers(false);

        if (handler == null) {
            final ConsoleHandler consoleHandler = new ConsoleHandler();
            consoleHandler.setFormatter(new Formatter() {
                @Override
                public String format(final LogRecord record) {
                    final StringBuffer sb = new StringBuffer();

                    sb.append("[");
                    sb.append(record.getLevel().getName());
                    sb.append("]\t");

                    sb.append(formatMessage(record));
                    sb.append("\n");

                    return sb.toString();
                }
            });
            logger.addHandler(consoleHandler);
        } else {
            logger.addHandler(handler);
        }

    }

    public static void configureLogging(final String loggerHandlerClassName, final Logger logger) {
        final Handler handler = loadLoggerHandlerByClassName(loggerHandlerClassName);
        configureLogging(handler, logger);
    }

    public static void logException(final Logger logger, final Exception ex) {
        logger.log(Level.SEVERE, ex.getMessage(), ex);
        if (throwOnErrors) {
            throw new RuntimeException(ex);
        }
    }
}
