using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using TodoListWebApp.Extensions;

namespace TodoListWebApp.Utils
{
    public class DomainResolver : IDisposable
    {
        
        private string signedInUseremail { get; set; }
        private string userObjectID { get; set; }
        private HttpContext _httpContext;
        public bool isB2cUser { get; set; } = false;

        private readonly AzureAdB2COptions _azureAdB2COptions;
        private readonly AzureAdOptions _azureAdOptions;

        public DomainResolver(HttpContext httpContext, AzureAdOptions azureAdOptions, AzureAdB2COptions azureAdB2COptions)
        {
            _azureAdOptions = azureAdOptions;
            _azureAdB2COptions = azureAdB2COptions;

            _httpContext = httpContext;
            userObjectID = (httpContext.User.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier"))?.Value;

            if (httpContext.User.FindFirst("emails") != null)
            {
                signedInUseremail = httpContext.User.FindFirst("emails").Value;
            }
            else
            {
                //"preferred_username"
                signedInUseremail = httpContext.User.FindFirst("preferred_username") != null ? httpContext.User.FindFirst("preferred_username").Value : null;
            }
            if (!signedInUseremail.ToLower().EndsWith("domain.com"))
            {
                isB2cUser = true;
            }


        }

        public async Task<AuthenticationResult> getAccessTokenAsync()
        {
            AuthenticationResult result = null;
            if (signedInUseremail.ToLower().EndsWith("domain.com"))
            {
                string signedInUserID = _httpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
                result = await ObtainTokenFromAzureAdAsync(signedInUserID, userObjectID);
            }
            else
            {
                string signedInUserID = _httpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value;
                result = await ObtainTokenFromAzureAdB2CAsync(signedInUserID);
            }
            return result;
        }

        private async Task<AuthenticationResult> ObtainTokenFromAzureAdB2CAsync(string signedInUserID)
        {
            // Retrieve the token with the specified scopes
            var scopes = _azureAdB2COptions.ApiScopes.Split(' ');
            TokenCache userTokenCache = new MSALSessionCache(signedInUserID, _httpContext).GetMsalCacheInstance();
            ConfidentialClientApplication cca = new ConfidentialClientApplication(_azureAdB2COptions.ClientId, _azureAdB2COptions.Authority, _azureAdB2COptions.RedirectUri, new ClientCredential(_azureAdB2COptions.ClientSecret), userTokenCache, null);

            var result = await cca.AcquireTokenSilentAsync(scopes, cca.Users.FirstOrDefault(), _azureAdB2COptions.Authority, false);
            return result;
        }

        private async Task<AuthenticationResult> ObtainTokenFromAzureAdAsync(string signedInUserID, string userObjectID)
        {
            var scopes = _azureAdOptions.ApiScopes.Split(' ');
            TokenCache userTokenCache = new MSALSessionCache(signedInUserID, _httpContext).GetMsalCacheInstance();

            // Using ADAL.Net, get a bearer token to access the TodoListService
            ConfidentialClientApplication cca = new ConfidentialClientApplication(_azureAdOptions.ClientId, _azureAdOptions.Authority, _azureAdOptions.RedirectUri, new ClientCredential(_azureAdOptions.ClientSecret), userTokenCache, null);
            var result = await cca.AcquireTokenSilentAsync(scopes, cca.Users.FirstOrDefault(), _azureAdOptions.Authority, false);
            return result;
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~DomainResolver() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }
}
