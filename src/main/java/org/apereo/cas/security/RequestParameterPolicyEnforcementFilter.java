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
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * This is a Java Servlet Filter that examines specified Request Parameters as to whether they contain specified
 * characters and as to whether they are multivalued throws an Exception if they do not meet configured rules.
 * <p>
 * Configuration:
 * <p>
 * The filter defaults to checking all request parameters for the hash, percent, question mark,
 * and ampersand characters, and enforcing no-multi-valued-ness.
 * <p>
 * You can turn off multi-value checking by setting the init-param "allowMultiValuedParameters" to "true".  Setting it
 * to "false" is a no-op retaining the default configuration.  Setting this parameter to any other value may fail filter
 * initialization.
 * <p>
 * You can change the set of request parameters being examined by setting the init-param "parametersToCheck" to a
 * whitespace delimited list of parameters to check.  Setting it to the special value "*" retains the default
 * behavior of checking all.  Setting it to a blank value may fail filter initialization.  Setting it to a String
 * containing the asterisk token and any additional token may fail filter initialization.
 * <p>
 * You can change the set of characters looked for by setting the init-param "charactersToForbid" to a whitespace
 * delimited list of characters to forbid.  Setting it to the special value "none" disables the illicit character
 * blocking feature of this Filter (for the case where you only want to use the mutli-valued-ness blocking).
 * Setting it to a blank value may fail filter initialization.
 * Setting it to a value that fails to parse perfectly
 * (e.g., a value with multi-character Strings between the whitespace delimiters)
 * may fail filter initialization.  The default set of characters disallowed is percent, hash, question mark,
 * and ampersand.
 * <p>
 * You can limit a set of request parameters to only be allowed on requests of type POST by
 * setting the init-param "onlyPostParameters" to a whitespace-delimited list of parameters.
 * Unlike "parametersToCheck", this does not support the special value "*".
 * Setting  "onlyPostParameters" to a blank value fails filter initialization.
 * By default (when "onlyPostParameters" is not set), the filter does not limit request parameters
 * to only POST requests.
 * <p>
 * You can set FilterUtils.throwOnErrors, and so whether configuration errors
 * cause filter init to fail, by setting the init-param "failSafe". Setting
 * failSafe to true makes configuration errors fatal thereby avoiding "unsafe"
 * partially configured filter states. Setting failSafe to false sets
 * FilterUtils.throwOnErrors to false (its default value).
 * <p>
 * NOTE: FilterUtils is a stateful static singleton service. Setting "failSafe"
 * configures FilterUtils globally.
 * <p>
 * Setting any other init parameter other than these recognized by this Filter will fail Filter initialization.  This
 * is to protect the adopter from typos or misunderstandings in web.xml configuration such that an intended
 * configuration might not have taken effect, since that might have security implications.
 * <p>
 * Setting the Filter to both allow multi-valued parameters and to disallow no characters would make the Filter a
 * no-op, and so may fail filter initialization since you probably meant the Filter to be doing something.
 * <p>
 * The intent of this filter is rough, brute force blocking of unexpected characters in specific CAS protocol related
 * request parameters.  This is one option as a workaround for patching in place certain Java CAS Client versions that
 * may be vulnerable to certain attacks involving crafted request parameter values that may be mishandled.  This is
 * also suitable for patching certain CAS Server versions to make more of an effort to detect and block out-of-spec
 * CAS protocol requests.  Aside from the intent to be useful for those cases, there is nothing CAS-specific about
 * this Filter itself.  This is a generic Filter for doing some pretty basic generic sanity checking on request
 * parameters.  It might come in handy the next time this kind of issue arises.
 * <p>
 * This Filter is written to have no external .jar dependencies aside from the Servlet API necessary to be a Filter.
 * <p>WARNING: Be sure that either FilterUtils throwOnErrors is set to true (not
 * its default value) or that you are reliably monitoring logs for SEVERE level
 * messages, so that you reliably notice if this filter is misconfigured. You
 * can set FilterUtils throwOnErrors by setting the "failSafe" init-param on
 * this filter. If FilterUtils throwOnErrors is false (its default value), this
 * Filter can init in inconsistent configuration states. This is what is meant
 * by "may fail filter initialization" above -- it'll fail only if FilterUtils
 * throwOnError is true (not its default configuration), otherwise it will just
 * log an exception.
 *
 * @since cas-security-filter 1.1
 */
public class RequestParameterPolicyEnforcementFilter extends AbstractSecurityFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(RequestParameterPolicyEnforcementFilter.class.getName());

    /**
     * The set of Characters blocked by default on checked parameters.
     * Expressed as a whitespace delimited set of characters.
     */
    public static final String DEFAULT_CHARACTERS_BLOCKED = "? & # %";

    /**
     * The name of the optional Filter init-param specifying what request parameters ought to be checked.
     * The value is a whitespace delimited set of parameters.
     * The exact value '*' has the special meaning of matching all parameters, and is the default behavior.
     */
    public static final String PARAMETERS_TO_CHECK = "parametersToCheck";

    /**
     * The name of the optional Filter init-param specifying what characters are forbidden in the checked request
     * parameters.  The value is a whitespace delimited set of such characters.
     */
    public static final String CHARACTERS_TO_FORBID = "charactersToForbid";

    /**
     * The name of the optional Filter init-param specifying whether the checked request parameters are allowed
     * to have multiple values.  Allowable values for this init parameter are `true` and `false`.
     */
    public static final String ALLOW_MULTI_VALUED_PARAMETERS = "allowMultiValuedParameters";


    /**
     * The name of the optional Filter init-param specifying what request parameters ought to be send via POST requests only.
     */
    public static final String ONLY_POST_PARAMETERS = "onlyPostParameters";

    /**
     * The name of the optional Filter init-param specifying that configuration
     * errors should be fatal.
     */
    public static final String FAIL_SAFE = "failSafe";

    /**
     * Set of parameter names to check.
     * Empty set represents special behavior of checking all parameters.
     */
    private Set<String> parametersToCheck;

    /**
     * Set of characters to forbid in the checked request parameters.
     * Empty set represents not forbidding any characters.
     */
    private Set<Character> charactersToForbid;

    /**
     * Should checked parameters be permitted to have multiple values.
     */
    private boolean allowMultiValueParameters = false;

    /**
     * Set of parameters which should be only received via POST requests.
     */
    private Set<String> onlyPostParameters;


    /* ========================================================================================================== */
    /* Filter methods */

    public void setParametersToCheck(Set<String> parametersToCheck) {
        this.parametersToCheck = parametersToCheck;
    }

    public void setCharactersToForbid(Set<Character> charactersToForbid) {
        this.charactersToForbid = charactersToForbid;
    }

    public void setAllowMultiValueParameters(boolean allowMultiValueParameters) {
        this.allowMultiValueParameters = allowMultiValueParameters;
    }

    public void setOnlyPostParameters(Set<String> onlyPostParameters) {
        this.onlyPostParameters = onlyPostParameters;
    }

    /**
     * Configure whether the filter should fail safe. Fail safe in this context
     * means failing to init rather than initing with a configuration that's
     * ambiguous and so may not be providing the intended protections. Fail
     * dangerous in this context means initing regardless of configuration
     * errors, which won't prevent the servlet context from initing, but which
     * might init a servlet context without the protections intended by
     * declaring and mapping this filter.
     * <p>
     * NOTE: This sets the throwOnErrors property of static singleton service
     * FilterUtils. This configuration is global for all uses of FilterUtils,
     * e.g. for usages in other filters.
     * @param failSafe
     */
    public void setFailSafe(boolean failSafe) {
      // if configured to fail safe, make configuration errors fatal so that
      // this filter will not init() with known-problematic configuration.
      FilterUtils.setThrowOnErrors(failSafe);
    }

    public RequestParameterPolicyEnforcementFilter() {
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

        // config failSafe first because specifies consequences of subsequent
        // config errors
        final String failSafeParam = filterConfig.getInitParameter(FAIL_SAFE);

        if (null != failSafeParam) {
          setFailSafe(
            FilterUtils.parseStringToBooleanDefaultingToFalse(failSafeParam));
        }

        // verify there are no init parameters configured that are not recognized
        // since an unrecognized init param might be the adopter trying to configure this filter in an important way
        // and accidentally ignoring that intent might have security implications.
        final Enumeration initParamNames = filterConfig.getInitParameterNames();
        throwIfUnrecognizedParamName(initParamNames);

        final String initParamAllowMultiValuedParameters = filterConfig.getInitParameter(ALLOW_MULTI_VALUED_PARAMETERS);
        final String initParamParametersToCheck = filterConfig.getInitParameter(PARAMETERS_TO_CHECK);
        final String initParamOnlyPostParameters = filterConfig.getInitParameter(ONLY_POST_PARAMETERS);
        final String initParamCharactersToForbid = filterConfig.getInitParameter(CHARACTERS_TO_FORBID);

        try {
            this.allowMultiValueParameters = FilterUtils.parseStringToBooleanDefaultingToFalse(initParamAllowMultiValuedParameters);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing request parameter [" + ALLOW_MULTI_VALUED_PARAMETERS
                    + "] with value [" + initParamAllowMultiValuedParameters + "]", e));
        }

        try {
            this.parametersToCheck = parseParametersList(initParamParametersToCheck, true);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing request parameter " + PARAMETERS_TO_CHECK + " with value ["
                    + initParamParametersToCheck + "]", e));
        }
        try {
            this.onlyPostParameters = parseParametersList(initParamOnlyPostParameters, false);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing request parameter " + ONLY_POST_PARAMETERS + " with value ["
                    + initParamOnlyPostParameters + "]", e));
        }

        try {
            this.charactersToForbid = parseCharactersToForbid(initParamCharactersToForbid);
        } catch (final Exception e) {
            FilterUtils.logException(LOGGER, new ServletException("Error parsing request parameter " + CHARACTERS_TO_FORBID + " with value [" +
                    initParamCharactersToForbid + "]", e));
        }

        if (this.allowMultiValueParameters && this.charactersToForbid.isEmpty()) {
            FilterUtils.logException(LOGGER, new ServletException("Configuration to allow multi-value parameters and forbid no characters makes "
                    + getClass().getSimpleName() + " a no-op, which is probably not what you want, " +
                    "so failing Filter init."));
        }

    }


    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        try {

            if (request instanceof HttpServletRequest) {
                final HttpServletRequest httpServletRequest = (HttpServletRequest) request;

                // immutable map from String param name --> String[] parameter values
                final Map parameterMap = httpServletRequest.getParameterMap();

                // which parameters *on this request* ought to be checked.
                final Set<String> parametersToCheckHere;

                if (this.parametersToCheck.isEmpty()) {
                    // the special meaning of empty is to check *all* the parameters, so
                    parametersToCheckHere = parameterMap.keySet();
                } else {
                    parametersToCheckHere = this.parametersToCheck;
                }

                if (!this.allowMultiValueParameters) {
                    requireNotMultiValued(parametersToCheckHere, parameterMap);
                }

                enforceParameterContentCharacterRestrictions(parametersToCheckHere,
                        this.charactersToForbid, parameterMap);

                checkOnlyPostParameters(httpServletRequest.getMethod(), parameterMap, this.onlyPostParameters);
            }
        } catch (final Exception e) {
            // translate to a ServletException to meet the typed expectations of the Filter API.
            FilterUtils.logException(LOGGER, new ServletException(getClass().getSimpleName() + " is blocking this request.  Examine the cause in" +
                    " this stack trace to understand why.", e));
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // do nothing
    }

    /* ========================================================================================================== */
    /* Init parameter parsing */

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
     * @throws ServletException if unrecognized parameter name is present
     */
    static void throwIfUnrecognizedParamName(Enumeration initParamNames) throws ServletException {
        final Set<String> recognizedParameterNames = new HashSet<String>();
        recognizedParameterNames.add(ALLOW_MULTI_VALUED_PARAMETERS);
        recognizedParameterNames.add(PARAMETERS_TO_CHECK);
        recognizedParameterNames.add(ONLY_POST_PARAMETERS);
        recognizedParameterNames.add(CHARACTERS_TO_FORBID);
        recognizedParameterNames.add(FAIL_SAFE);
        recognizedParameterNames.add(LOGGER_HANDLER_CLASS_NAME);

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

    /**
     * Returns the logger instance.
     *
     * @return Configured logger handler, or SLF4j handler, or JUL's default.
     */
    Logger getLogger() {
        return LOGGER;
    }


    /**
     * Parse the whitespace delimited String of parameters to check.
     * <p>
     * If the String is null, return the empty set.
     * If the whitespace delimited String contains no tokens, throw IllegalArgumentException.
     * If the sole token is an asterisk, return the empty set.
     * If the asterisk token is encountered among other tokens, throw IllegalArgumentException.
     * <p>
     * This method returning an empty Set has the special meaning of "check all parameters".
     * <p>
     * This is a stateless static method.
     * <p>
     * This method is an implementation detail and is not exposed API.
     * This method is only non-private to allow JUnit testing.
     *
     * @param initParamValue null, or a non-blank whitespace delimited list of parameters to check
     * @param allowWildcard  whether a wildcard is allowed instead of the parameters list
     * @return a Set of String names of parameters to check, or an empty set representing check-them-all.
     * @throws IllegalArgumentException when the init param value is out of spec
     */
    static Set<String> parseParametersList(final String initParamValue, final boolean allowWildcard) {

        final Set<String> parameterNames = new HashSet<String>();

        if (null == initParamValue) {
            return parameterNames;
        }

        final String[] tokens = initParamValue.split("\\s+");

        if (0 == tokens.length) {
            FilterUtils.logException(LOGGER, new IllegalArgumentException("[" + initParamValue +
                    "] had no tokens but should have had at least one token."));
        }

        if (1 == tokens.length && "*".equals(tokens[0]) && allowWildcard) {
            return parameterNames;
        }

        for (final String parameterName : tokens) {

            if ("*".equals(parameterName)) {
                FilterUtils.logException(LOGGER, new IllegalArgumentException("Star token encountered among other tokens in parsing [" + initParamValue + "]"));
            }

            parameterNames.add(parameterName);
        }

        return parameterNames;
    }

    /**
     * Parse a whitespace delimited set of Characters from a String.
     * <p>
     * If the String is null (init param was not set) default to DEFAULT_CHARACTERS_BLOCKED.
     * If the String is "none" parse to empty set meaning block no characters.
     * If the String is empty throw, to avoid configurer accidentally configuring not to block any characters.
     *
     * @param paramValue value of the init param to parse
     * @return non-null Set of zero or more Characters to block
     */
    static Set<Character> parseCharactersToForbid(String paramValue) {

        final Set<Character> charactersToForbid = new HashSet<Character>();

        if (null == paramValue) {
            paramValue = DEFAULT_CHARACTERS_BLOCKED;
        }

        if ("none".equals(paramValue)) {
            return charactersToForbid;
        }

        final String[] tokens = paramValue.split("\\s+");

        if (0 == tokens.length) {
            FilterUtils.logException(LOGGER, new IllegalArgumentException("Expected tokens when parsing [" + paramValue + "] but found no tokens."
                    + " If you really want to configure no characters, use the magic value 'none'."));
        }

        for (final String token : tokens) {

            if (token.length() > 1) {
                FilterUtils.logException(LOGGER, new IllegalArgumentException("Expected tokens of length 1 but found [" + token + "] when " +
                        "parsing [" + paramValue + "]"));
            }

            final Character character = token.charAt(0);
            charactersToForbid.add(character);
        }

        return charactersToForbid;
    }

    /* ========================================================================================================== */
    /* Filtering requests */

    /**
     * For each parameter to check, verify that it has zero or one value.
     * <p>
     * The Set of parameters to check MAY be empty.
     * The parameter map MAY NOT contain any given parameter to check.
     * <p>
     * This method is an implementation detail and is not exposed API.
     * This method is only non-private to allow JUnit testing.
     * <p>
     * <p>
     * Static, stateless method.
     *
     * @param parametersToCheck non-null potentially empty Set of String names of parameters
     * @param parameterMap      non-null Map from String name of parameter to String[] values
     * @throws IllegalStateException if a parameterToCheck is present in the parameterMap with multiple values.
     */
    static void requireNotMultiValued(final Set<String> parametersToCheck, final Map parameterMap) {

        for (final String parameterName : parametersToCheck) {
            if (parameterMap.containsKey(parameterName)) {
                final String[] values = (String[]) parameterMap.get(parameterName);
                if (values.length > 1) {
                    FilterUtils.logException(LOGGER, new IllegalStateException("Parameter [" + parameterName + "] had multiple values [" +
                            Arrays.toString(values) + "] but at most one value is allowable."));
                }
            }
        }

    }

    /**
     * For each parameter to check, for each value of that parameter, check that the value does not contain
     * forbidden characters.
     * <p>
     * This is a stateless static method.
     * <p>
     * This method is an implementation detail and is not exposed API.
     * This method is only non-private to allow JUnit testing.
     *
     * @param parametersToCheck  Set of String request parameter names to look for
     * @param charactersToForbid Set of Character characters to forbid
     * @param parameterMap       String --> String[] Map, in practice as read from ServletRequest
     */
    static void enforceParameterContentCharacterRestrictions(
            final Set<String> parametersToCheck, final Set<Character> charactersToForbid, final Map parameterMap) {

        if (charactersToForbid.isEmpty()) {
            // short circuit
            return;
        }

        for (final String parameterToCheck : parametersToCheck) {

            final String[] parameterValues = (String[]) parameterMap.get(parameterToCheck);

            if (null != parameterValues) {

                for (final String parameterValue : parameterValues) {

                    for (final Character forbiddenCharacter : charactersToForbid) {

                        final StringBuilder characterAsStringBuilder = new StringBuilder();
                        characterAsStringBuilder.append(forbiddenCharacter);

                        if (parameterValue.contains(characterAsStringBuilder)) {
                            FilterUtils.logException(LOGGER, new IllegalArgumentException("Disallowed character [" + forbiddenCharacter
                                    + "] found in value [" + parameterValue + "] of parameter named ["
                                    + parameterToCheck + "]"));
                        }

                        // that forbiddenCharacter was not in this parameterValue
                    }

                    // none of the charactersToForbid were in this parameterValue
                }

                // none of the values of this parameterToCheck had a forbidden character
            } // or this parameterToCheck had null value

        }

        // none of the values of any of the parametersToCheck had a forbidden character
        // hurray! allow flow to continue without throwing an Exception.
    }

    /**
     * Check that some parameters should only be in POST requests (according to the configuration).
     *
     * @param method             the method of the request
     * @param parameterMap       all the request parameters
     * @param onlyPostParameters parameters that should only be in POST requests
     */
    static void checkOnlyPostParameters(final String method, final Map parameterMap, final Set<String> onlyPostParameters) {
        if (!"POST".equals(method)) {
            Set<String> names = parameterMap.keySet();
            for (String onlyPostParameter : onlyPostParameters) {
                if (names.contains(onlyPostParameter)) {
                    FilterUtils.logException(LOGGER, new IllegalArgumentException(onlyPostParameter + " parameter should only be used in POST requests"));
                }
            }
        }
    }


}
