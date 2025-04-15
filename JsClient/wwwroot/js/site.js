oidc.Log.setLogger(console);

const url = window.location.origin

const userManager = new oidc.UserManager({
    authority: "https://localhost:5000",
    client_id: "js-client",
    redirect_uri: url + "/SigninCallback",
    post_logout_redirect_uri: url + "/SignOutCallback",
    response_type: "code",
    scope: "openid offline_access",
    response_mode: "query",
    silent_redirect_uri: url + "/SigninSilentCallback",
    automaticSilentRenew: true,
    userStore: new oidc.WebStorageStateStore({store: window.localStorage}),
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
