using System.Security.Cryptography.X509Certificates;
using AuthenticationServer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthenticationServer.Data;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var path = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
var dbPath = Path.Combine(path, "account.db");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlite($"Data Source={dbPath}");

    // Register the entity sets needed by OpenIddict.
    // Note: use the generic overload if you need to replace the default OpenIddict entities.
    options.UseOpenIddict();
});
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
       .AddRoles<IdentityRole>() // can phai AddRoles neu AddDefaultIdentity<IdentityUser>
       .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddControllersWithViews();

#region OpenIddict Configuration

builder.Services.AddOpenIddict()

       // Register the OpenIddict core components.
       .AddCore(options =>
       {
           // Configure OpenIddict to use the Entity Framework Core stores and models.
           // Note: call ReplaceDefaultEntities() to replace the default entities.
           options.UseEntityFrameworkCore()
                  .UseDbContext<ApplicationDbContext>();
       })

       // Register the OpenIddict server components.
       .AddServer(options =>
       {
           // Enable the token endpoint.
           options.SetAuthorizationEndpointUris("connect/authorize")
                  .SetEndSessionEndpointUris("connect/logout")
                  .SetTokenEndpointUris("connect/token")
                  .SetUserInfoEndpointUris("connect/userinfo");

           // Enable the client credentials flow.
           options.AllowClientCredentialsFlow()
                  .AllowAuthorizationCodeFlow()
                  .AllowPasswordFlow()
                  .AllowRefreshTokenFlow();

           // Mark the "email", "profile" and "roles" scopes as supported scopes.
           options.RegisterScopes(OpenIddictConstants.Permissions.Scopes.Phone, OpenIddictConstants.Permissions.Scopes.Email, OpenIddictConstants.Permissions.Scopes.Profile, OpenIddictConstants.Permissions.Scopes.Roles);

           const string encryptionFileName = "EncryptionCertificate.pfx";
           const string signingFileName = "SigningCertificate.pfx";
           var encryptionCertificatePath = Path.Combine(AppContext.BaseDirectory, "Certificates", encryptionFileName);
           var signingCertificatePath = Path.Combine(AppContext.BaseDirectory, "Certificates", signingFileName);
           // Register the signing and encryption credentials.
           options.AddEncryptionCertificate(new X509Certificate2(encryptionCertificatePath))
                  .AddSigningCertificate(new X509Certificate2(signingCertificatePath));

           // Register the ASP.NET Core host and configure the ASP.NET Core options.
           options.UseAspNetCore()
                  .EnableAuthorizationEndpointPassthrough()
                  .EnableEndSessionEndpointPassthrough()
                  .EnableTokenEndpointPassthrough()
                  .EnableUserInfoEndpointPassthrough()
                  .EnableStatusCodePagesIntegration();

           // options.SetAccessTokenLifetime(TimeSpan.FromSeconds(10));
           // options.SetRefreshTokenLifetime(TimeSpan.FromSeconds(10));
       });
;

#endregion

// Register the worker responsible for seeding the database.
// Note: in a real world application, this step should be part of a setup script.
builder.Services.AddHostedService<Worker>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("allow",
        policy =>
        {
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseCors("allow");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();