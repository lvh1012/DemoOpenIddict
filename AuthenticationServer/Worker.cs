using AuthenticationServer.Data;
using OpenIddict.Abstractions;

namespace AuthenticationServer;

public class Worker(IServiceProvider serviceProvider) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = serviceProvider.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync();

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        if (await manager.FindByClientIdAsync("js-client") is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "js-client",
                ClientType = OpenIddictConstants.ClientTypes.Public,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                ApplicationType = OpenIddictConstants.ApplicationTypes.Web,
                RedirectUris = { new Uri("https://localhost:5010/SigninCallback"), new Uri("https://localhost:5010/SigninSilentCallback") },
                PostLogoutRedirectUris = { new Uri("https://localhost:5010/SignOutCallback") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token, // lay refresh token
                    OpenIddictConstants.Permissions.Endpoints.Authorization, // lay authoriztion code
                    OpenIddictConstants.Permissions.Endpoints.EndSession, // logout
                    OpenIddictConstants.Permissions.Endpoints.Revocation, // Revoke tokens on signout
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Scopes.Profile
                }
            });
        }

        if (await manager.FindByClientIdAsync("mvc-client") is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "mvc-client",
                ClientSecret = "mvc-client",
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                ApplicationType = OpenIddictConstants.ApplicationTypes.Web,
                RedirectUris = { new Uri("https://localhost:5020/SigninCallback"), new Uri("https://localhost:5020/SigninSilentCallback") },
                PostLogoutRedirectUris = { new Uri("https://localhost:5020/SignOutCallback") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token, // lay refresh token
                    OpenIddictConstants.Permissions.Endpoints.Authorization, // lay authoriztion code
                    OpenIddictConstants.Permissions.Endpoints.EndSession, // logout
                    OpenIddictConstants.Permissions.Endpoints.Revocation, // Revoke tokens on signout
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Scopes.Profile
                }
            });
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}