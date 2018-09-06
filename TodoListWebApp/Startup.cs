using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using TodoListWebApp.Extensions;

namespace WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public AzureAdB2COptions azureAdB2COptions { get; set; }
        public AzureAdOptions azureAdOptions { get; set; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            azureAdB2COptions = new AzureAdB2COptions();
            Configuration.Bind("AzureAdB2C", azureAdB2COptions);

            azureAdOptions = new AzureAdOptions();
            Configuration.Bind("AzureAd", azureAdOptions);

            services.Configure<AzureAdB2COptions>(options => Configuration.GetSection("AzureAdB2C").Bind(options));
            services.Configure<AzureAdOptions>(options => Configuration.GetSection("AzureAd").Bind(options));
            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddOpenIdConnect(options =>
            {
                options.Authority = $"{Configuration["AzureAd:Instance"]}{Configuration["AzureAd:TenantId"]}/v2.0/";
                options.ClientId = Configuration["AzureAd:ClientId"];
                options.RequireHttpsMetadata = false;
                options.CallbackPath = Configuration["AzureAd:CallbackPath"];
                options.SignedOutCallbackPath = Configuration["AzureAd:SignOutCallbackPath"];
                options.UseTokenLifetime = true;
                options.ResponseType = OpenIdConnectResponseType.Code + " " + OpenIdConnectResponseType.IdToken;
                options.ResponseMode = "form_post";
                options.SaveTokens = true;
                options.TokenValidationParameters = new TokenValidationParameters() { NameClaimType = "name", ValidateIssuer = false };
                options.Events = new OpenIdConnectEvents()
                {
                    OnRemoteFailure = OnRemoteFailureAsync,
                    OnAuthorizationCodeReceived = OnAuthorizationCodeReceivedAsync
                    //OnAuthenticationFailed = OnAuthenticationFailedAsync
                };
            })
            .AddOpenIdConnect("AzureAdB2C", options =>
            {
                options.Authority = $"{Configuration["AzureAdB2C:Instance"]}{Configuration["AzureAdB2C:TenantId"]}/{Configuration["AzureAdB2C:SignUpSignInPolicyId"]}/v2.0/";
                options.ClientId = Configuration["AzureAdB2C:ClientId"];
                options.RequireHttpsMetadata = false;
                options.SignedOutCallbackPath = Configuration["AzureAdB2C:SignOutCallbackPath"];
                options.CallbackPath = Configuration["AzureAdB2C:CallbackPath"];
                options.TokenValidationParameters = new TokenValidationParameters() { NameClaimType = "name", ValidateIssuer = false };
                options.Resource = "https://graph.windows.net";
                options.Events = new OpenIdConnectEvents()
                {
                    OnRedirectToIdentityProvider = OnRedirectToIdentityProviderB2CAsync,
                    OnRemoteFailure = OnRemoteFailureB2cAsync,
                    OnAuthorizationCodeReceived = OnAuthorizationCodeReceivedB2CAsync
                };
            })
            .AddCookie();


            services.AddMvc()
                .AddSessionStateTempDataProvider();
            services.AddSession();
        }


        /// <summary>
        /// Redeems the authorization code by calling AcquireTokenByAuthorizationCodeAsync in order to ensure
        /// that the cache has a token for the signed-in user, which will then enable the controllers (like the
        /// TodoController, to call AcquireTokenSilentAsync successfully.
        /// </summary>
        private async Task OnAuthorizationCodeReceivedAsync(AuthorizationCodeReceivedContext context)
        {
            // Acquire a Token for the Graph API and cache it using ADAL. In the TodoListController, we'll use the cache to acquire a token for the Todo List API
            string userObjectId = (context.Principal.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier"))?.Value;
            string signedInUserID = context.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
            var code = context.ProtocolMessage.Code;
            TokenCache userTokenCache = new MSALSessionCache(signedInUserID, context.HttpContext).GetMsalCacheInstance();

            ConfidentialClientApplication cca = new ConfidentialClientApplication(azureAdOptions.ClientId, azureAdOptions.Authority, azureAdOptions.RedirectUri, new ClientCredential(azureAdOptions.ClientSecret), userTokenCache, null);
            try
            {
                var scopes = azureAdOptions.ApiScopes.Split(' ');
                var result = await cca.AcquireTokenByAuthorizationCodeAsync(code, scopes);
                //AcquireTokenSilentAsync(scopes, cca.Users.FirstOrDefault(), azureAdOptions.Authority, false);


                context.HandleCodeRedemption(result.AccessToken, result.IdToken);
            }
            catch (Exception ex)
            {
                //TODO: Handle
                throw;
            }
            // Notify the OIDC middleware that we already took care of code redemption.
        }

        /// <summary>
        /// this method is invoked if exceptions are thrown during request processing
        /// </summary>
        //private Task OnAuthenticationFailedAsync(AuthenticationFailedContext context)
        //{
        //    context.HandleResponse();
        //    context.Response.Redirect("/Home/Error?message=" + context.Exception.Message);
        //    return Task.FromResult(0);
        //}


        public Task OnRemoteFailureAsync(RemoteFailureContext context)
        {
            context.HandleResponse();
            // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page 
            // because password reset is not supported by a "sign-up or sign-in policy"
            if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("AADB2C90118"))
            {
                // If the user clicked the reset password link, redirect to the reset password route
                context.Response.Redirect("/Session/ResetPassword");
            }
            else if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied"))
            {
                context.Response.Redirect("/");
            }
            else
            {
                context.Response.Redirect("/Home/Error?message=" + context.Failure.Message);
            }
            return Task.FromResult(0);
        }





        public Task OnRedirectToIdentityProviderB2CAsync(RedirectContext context)
        {
            var defaultPolicy = azureAdB2COptions.DefaultPolicy;
            if (context.Properties.Items.TryGetValue(AzureAdB2COptions.PolicyAuthenticationProperty, out var policy) &&
                !policy.Equals(defaultPolicy))
            {
                context.ProtocolMessage.Scope = OpenIdConnectScope.OpenIdProfile;
                context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.ToLower().Replace(defaultPolicy.ToLower(), policy.ToLower());
                context.Properties.Items.Remove(AzureAdB2COptions.PolicyAuthenticationProperty);
            }
            else if (!string.IsNullOrEmpty(azureAdB2COptions.ApiUrl))
            {
                context.ProtocolMessage.Scope += $" offline_access {azureAdB2COptions.ApiScopes}";
                context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.CodeIdToken;
            }
            return Task.FromResult(0);
        }



        public Task OnRemoteFailureB2cAsync(RemoteFailureContext context)
        {
            context.HandleResponse();
            // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page 
            // because password reset is not supported by a "sign-up or sign-in policy"
            if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("AADB2C90118"))
            {
                // If the user clicked the reset password link, redirect to the reset password route
                context.Response.Redirect("/Session/ResetPassword");
            }
            else if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied"))
            {
                context.Response.Redirect("/");
            }
            else
            {
                context.Response.Redirect("/Home/Error?message=" + context.Failure.Message);
            }
            return Task.FromResult(0);
        }

        public async Task OnAuthorizationCodeReceivedB2CAsync(AuthorizationCodeReceivedContext context)
        {
            // Use MSAL to swap the code for an access token
            // Extract the code from the response notification
            var code = context.ProtocolMessage.Code;

            string signedInUserID = context.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
            TokenCache userTokenCache = new MSALSessionCache(signedInUserID, context.HttpContext).GetMsalCacheInstance();

            ConfidentialClientApplication cca = new ConfidentialClientApplication(azureAdB2COptions.ClientId, azureAdB2COptions.Authority, azureAdB2COptions.RedirectUri, new ClientCredential(azureAdB2COptions.ClientSecret), userTokenCache, null);
            try
            {
                AuthenticationResult result = await cca.AcquireTokenByAuthorizationCodeAsync(code, azureAdB2COptions.ApiScopes.Split(' '));


                context.HandleCodeRedemption(result.AccessToken, result.IdToken);
            }
            catch (Exception ex)
            {
                //TODO: Handle
                throw;
            }
        }




        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseSession(); // Needs to be app.UseAuthentication() and app.UseMvc() otherwise you will get an exception "Session has not been configured for this application or request."
            app.UseAuthentication();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
