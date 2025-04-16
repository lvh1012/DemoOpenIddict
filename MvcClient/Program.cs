using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Cookies;
using OpenIddict.Abstractions;
using OpenIddict.Client;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(options =>
       {
           options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
       })

       .AddCookie(options =>
       {
           options.LoginPath = "/LogIn";
           options.LogoutPath = "/LogOut";
           options.ExpireTimeSpan = TimeSpan.FromMinutes(50);
           options.SlidingExpiration = true;
       });

builder.Services.AddOpenIddict()

       // Register the OpenIddict core components.
       .AddCore(options =>
       {

       })

       // Register the OpenIddict client components.
       .AddClient(options =>
       {
           // Note: this sample uses the code flow, but you can enable the other flows if necessary.
           options.AllowAuthorizationCodeFlow();

           const string encryptionFileName = "EncryptionCertificate.pfx";
           const string signingFileName = "SigningCertificate.pfx";
           var encryptionCertificatePath = Path.Combine(AppContext.BaseDirectory, "Certificates", encryptionFileName);
           var signingCertificatePath = Path.Combine(AppContext.BaseDirectory, "Certificates", signingFileName);
           // Register the signing and encryption credentials.
           options.AddEncryptionCertificate(new X509Certificate2(encryptionCertificatePath))
                  .AddSigningCertificate(new X509Certificate2(signingCertificatePath));

           // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
           options.UseAspNetCore()
                  .EnableStatusCodePagesIntegration()
                  .EnableRedirectionEndpointPassthrough()
                  .EnablePostLogoutRedirectionEndpointPassthrough();

           // Register the System.Net.Http integration and use the identity of the current
           // assembly as a more specific user agent, which can be useful when dealing with
           // providers that use the user agent as a way to throttle requests (e.g Reddit).
           options.UseSystemNetHttp()
                  .SetProductInformation(typeof(Program).Assembly);

           // Add a client registration matching the client application definition in the server project.
           options.AddRegistration(new OpenIddictClientRegistration
           {
               Issuer = new Uri("https://localhost:5000/", UriKind.Absolute),
               ClientId = "mvc-client",
               ClientSecret = "mvc-client",
               Scopes =
               {
                   "scp:openid",            // 👈 Thêm thủ công
                   "scp:profile",           // 👈 Thêm thủ công
                   "scp:offline_access",    // 👈 Thêm thủ công
                   "scp:email",
                   "scp:roles",
                   "scp:phone"
               },

               // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
               // URI per provider, unless all the registered providers support returning a special "iss"
               // parameter containing their URL as part of authorization responses. For more information,
               // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
               RedirectUri = new Uri("SigninCallback", UriKind.Relative),
               PostLogoutRedirectUri = new Uri("SignOutCallback", UriKind.Relative)
           });
       });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
