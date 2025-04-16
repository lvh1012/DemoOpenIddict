oidc.Log.setLogger(console);

const url = window.location.origin;
const issuer = "https://localhost:5000";

const userManager = new oidc.UserManager({
    // The authority URL of the OpenID Connect provider
    authority: issuer,

    // The client ID registered with the OpenID Connect provider
    client_id: "js-client",

    // The URI to redirect to after login
    redirect_uri: url + "/SigninCallback",

    // The URI to redirect to after logout
    post_logout_redirect_uri: url + "/SignOutCallback",

    // The response type for the authentication flow
    response_type: "code",

    // The scopes requested for the token
    scope: "openid profile offline_access",

    // The response mode for the authentication flow
    response_mode: "query",

    // The URI for silent token renewal
    silent_redirect_uri: url + "/SigninSilentCallback",

    // Time before token expiration to trigger a notification
    accessTokenExpiringNotificationTimeInSeconds: 60,

    // Automatically renew the token silently
    automaticSilentRenew: true,

    // Interval to check the session state
    checkSessionIntervalInSeconds: 10,

    // Authentication method for the client
    client_authentication: "client_secret_post",

    // Include ID token in silent renew requests
    includeIdTokenInSilentRenew: true,

    // Exclude ID token in silent signout requests
    includeIdTokenInSilentSignout: false,

    // Disable loading user info from the user info endpoint
    loadUserInfo: false,

    // Monitor anonymous sessions
    monitorAnonymousSession: true,

    // Monitor authenticated sessions
    monitorSession: true,

    // Revoke tokens on signout
    revokeTokensOnSignout: true,

    // Specify the types of tokens to revoke
    revokeTokenTypes: ["access_token", "refresh_token"],

    // Use local storage to store user state
    userStore: new oidc.WebStorageStateStore({store: window.localStorage}),

    metadata: {
        token_endpoint: issuer + "/connect/token",
        revocation_endpoint: issuer + "/connect/revocation",
        end_session_endpoint: issuer + "/connect/logout",
        authorization_endpoint: issuer + "/connect/authorize",
        userinfo_endpoint: issuer + "/connect/userinfo",
    }
});

function getUserInfo() {
    return userManager.getUser();
}

function login() {
    return userManager.signinRedirect();
}

function logout() {
    return userManager.signoutRedirect();
}

function refreshToken() {
    return userManager.signinSilent();
}

