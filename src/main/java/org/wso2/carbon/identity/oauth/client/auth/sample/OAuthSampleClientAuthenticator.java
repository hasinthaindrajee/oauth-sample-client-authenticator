package org.wso2.carbon.identity.oauth.client.auth.sample;

import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.AbstractOAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

public class OAuthSampleClientAuthenticator extends AbstractOAuthClientAuthenticator {

    public boolean authenticateClient(HttpServletRequest httpServletRequest,
                                      Map<String, List> map, OAuthClientAuthnContext oAuthClientAuthnContext)
            throws OAuthClientAuthnException {
        String clientId = httpServletRequest.getHeader("client_id");
        String clientSecret = httpServletRequest.getHeader("client_secret");
        try {
            return OAuth2Util.authenticateClient(clientId, clientSecret);
        } catch (IdentityOAuthAdminException | InvalidOAuthClientException | IdentityOAuth2Exception e) {
            throw new OAuthClientAuthnException("Error while authenticating client", "INVALID_CLIENT", e);
        }
    }

    public boolean canAuthenticate(HttpServletRequest httpServletRequest, Map<String, List> map,
                                   OAuthClientAuthnContext oAuthClientAuthnContext) {
        if (httpServletRequest.getHeader("client_id") != null &&
                httpServletRequest.getHeader("client_secret") != null) {
            return true;
        }
        return false;
    }

    public String getClientId(HttpServletRequest httpServletRequest, Map<String, List> map,
                              OAuthClientAuthnContext oAuthClientAuthnContext) throws OAuthClientAuthnException {
        return httpServletRequest.getHeader("client_id");
    }

    @Override
    public int getPriority() {
        return 150;
    }

    @Override
    public String getName() {
        return "SampleOAuthClientAuthenticator";
    }
}
