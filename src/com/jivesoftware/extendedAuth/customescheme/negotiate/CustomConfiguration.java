/*
 * $Revision$
 * $Date$
 *
 * Copyright (C) 1999-2012 Jive Software. All rights reserved.
 *
 * This software is the proprietary information of Jive Software. Use is subject to license terms.
 */
package com.jivesoftware.extendedAuth.customescheme.negotiate;

import java.util.Collections;
import java.util.Map;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;


/**
 * Created with IntelliJ IDEA.
 * User: dov2
 * Date: 7/3/12
 * Time: 3:22 PM
 * To change this template use File | Settings | File Templates.
 */
public class CustomConfiguration extends Configuration {
    //~ Instance fields ================================================================================================

    private final AppConfigurationEntry[] defaultConfiguration;
    private final Map<String, AppConfigurationEntry[]> mappedConfigurations;

    //~ Constructors ===================================================================================================

    /**
     * Creates a new instance with only a defaultConfiguration. Any
     * configuration name will result in defaultConfiguration being returned.
     *
     * @param defaultConfiguration
     *            The result for any calls to
     *            {@link #getAppConfigurationEntry(String)}. Can be
     *            <code>null</code>.
     */
    public CustomConfiguration(AppConfigurationEntry[] defaultConfiguration) {
        this(Collections.<String, AppConfigurationEntry[]>emptyMap(), defaultConfiguration);
    }

    /**
     * Creates a new instance with a mapping of login context name to an array
     * of {@link javax.security.auth.login.AppConfigurationEntry}s.
     *
     * @param mappedConfigurations
     *            each key represents a login context name and each value is an
     *            Array of {@link javax.security.auth.login.AppConfigurationEntry}s that should be used.
     */
    public CustomConfiguration(Map<String, AppConfigurationEntry[]> mappedConfigurations) {
        this(mappedConfigurations, null);
    }

    /**
     * Creates a new instance with a mapping of login context name to an array
     * of {@link javax.security.auth.login.AppConfigurationEntry}s along with a default configuration that
     * will be used if no mapping is found for the given login context name.
     *
     * @param mappedConfigurations
     *            each key represents a login context name and each value is an
     *            Array of {@link javax.security.auth.login.AppConfigurationEntry}s that should be used.
     * @param defaultConfiguration The result for any calls to
     *            {@link #getAppConfigurationEntry(String)}. Can be
     *            <code>null</code>.
     */
    public CustomConfiguration(Map<String, AppConfigurationEntry[]> mappedConfigurations,
                               AppConfigurationEntry[] defaultConfiguration) {
        // Assert.notNull(mappedConfigurations, "mappedConfigurations cannot be null.");
        this.mappedConfigurations = mappedConfigurations;
        this.defaultConfiguration = defaultConfiguration;
    }

    //~ Methods ========================================================================================================

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        AppConfigurationEntry[] mappedResult = mappedConfigurations.get(name);
        return mappedResult == null ? defaultConfiguration : mappedResult;
    }

    /**
     * Does nothing, but required for JDK5
     */
    public void refresh() {
    }
}
