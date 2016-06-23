package org.apereo.cas.security;

/**
 * This is {@link AbstractSecurityFilter}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
public abstract class AbstractSecurityFilter {

    /** Describes the handler that should be used for logging. If none is defined
     * the filter will switch to a {@link java.util.logging.ConsoleHandler}.
     */
    public static final String LOGGER_HANDLER_CLASS_NAME = "loggerHandlerClassName";
    
    private String loggerHandlerClassName = "org.slf4j.bridge.SLF4JBridgeHandler";

    public void setLoggerHandlerClassName(final String loggerHandlerClassName) {
        this.loggerHandlerClassName = loggerHandlerClassName;
    }

    public String getLoggerHandlerClassName() {
        return loggerHandlerClassName;
    }
}
