/**
 * @author Nick Littlefield
 */

package org.openhds.server.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("security.jwt")
public class SecurityProperties {
    private String secret;
    private long expirationTime;
    private String headerString;
    private String tokenPrefix;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpirationTime() {
        return expirationTime;
    }

    public void setExpirationTime(long expirationTime) {
        this.expirationTime = expirationTime;
    }

    public String getHeaderString() {
        return headerString;
    }

    public void setHeaderString(String headerString) {
        this.headerString = headerString;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }
}
