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
                RedirectUris = { new Uri("https://localhost:5010/SigninCallback") ,new Uri("https://localhost:6000/SigninSilentCallback")},
                PostLogoutRedirectUris = {new Uri("https://localhost:5010/SignOutCallback") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Token, // lay refresh token
                    OpenIddictConstants.Permissions.Endpoints.Authorization, // lay authoriztion code
                    OpenIddictConstants.Permissions.Endpoints.EndSession, // logout
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Phone
                }
            });
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}