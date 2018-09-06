using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using TodoListWebApp.Extensions;
using TodoListWebApp.Models;
using TodoListWebApp.Utils;
using AuthenticationResult = Microsoft.Identity.Client.AuthenticationResult;
using ClientCredential = Microsoft.Identity.Client.ClientCredential;
using TokenCache = Microsoft.Identity.Client.TokenCache;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace TodoListWebApp.Controllers
{
    [Authorize]
    public class TodoController : Controller
    {
        private readonly AzureAdB2COptions _azureAdB2COptions;
        private AzureAdOptions _azureAdOptions;

        public TodoController(IOptions<AzureAdB2COptions> azureAdB2COptions, IOptions<AzureAdOptions> azureAdOptions)
        {
            _azureAdB2COptions = azureAdB2COptions.Value;
            _azureAdOptions = azureAdOptions.Value;
        }



        // GET: /<controller>/
        public async Task<IActionResult> Index()
        {
            
            List<TodoItem> itemList = new List<TodoItem>();
            AuthenticationResult result;
            try
            {
                
                // Because we signed-in already in the WebApp, the userObjectId is know
                
                using (var domainResolver = new DomainResolver(HttpContext,_azureAdOptions,_azureAdB2COptions))
                {
                    ViewBag.isB2cUser = domainResolver.isB2cUser;
                    result = await domainResolver.getAccessTokenAsync();
                }

                // Retrieve the user's To Do List.
                HttpClient client = new HttpClient();
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, _azureAdOptions.TodoListBaseAddress + "/api/todolist");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
                HttpResponseMessage response = await client.SendAsync(request);

                // Return the To Do List in the view.
                if (response.IsSuccessStatusCode)
                {
                    List<Dictionary<String, String>> responseElements = new List<Dictionary<String, String>>();
                    JsonSerializerSettings settings = new JsonSerializerSettings();
                    String responseString = await response.Content.ReadAsStringAsync();
                    responseElements = JsonConvert.DeserializeObject<List<Dictionary<String, String>>>(responseString, settings);
                    foreach (Dictionary<String, String> responseElement in responseElements)
                    {
                        TodoItem newItem = new TodoItem();
                        newItem.Title = responseElement["title"];
                        newItem.Owner = responseElement["owner"];
                        itemList.Add(newItem);
                    }

                    return View(itemList);
                }

                //
                // If the call failed with access denied, then drop the current access token from the cache, 
                //     and show the user an error indicating they might need to sign-in again.
                //
                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    return Unauthorized();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.InnerException);
                if (HttpContext.Request.Query["reauth"] == "True")
                {
                    //
                    // Send an OpenID Connect sign-in request to get a new set of tokens.
                    // If the user still has a valid session with Azure AD, they will not be prompted for their credentials.
                    // The OpenID Connect middleware will return to this controller after the sign-in response has been handled.
                    //
                    return new ChallengeResult(OpenIdConnectDefaults.AuthenticationScheme);
                }
                //
                // The user needs to re-authorize.  Show them a message to that effect.
                //
                TodoItem newItem = new TodoItem();
                newItem.Title = "(Sign-in required to view to do list.)";
                itemList.Add(newItem);
                ViewBag.ErrorMessage = "AuthorizationRequired";
                return View(itemList);
            }
            //
            // If the call failed for any other reason, show the user an error.
            //
            return View("Error");
        }

        //private async Task<AuthenticationResult> ObtainTokenFromAzureAdB2CAsync(string signedInUserID)
        //{
        //    // Retrieve the token with the specified scopes
        //    var scopes = _azureAdB2COptions.ApiScopes.Split(' ');
        //    TokenCache userTokenCache = new MSALSessionCache(signedInUserID, HttpContext).GetMsalCacheInstance();
        //    ConfidentialClientApplication cca = new ConfidentialClientApplication(_azureAdB2COptions.ClientId, _azureAdB2COptions.Authority, _azureAdB2COptions.RedirectUri, new ClientCredential(_azureAdB2COptions.ClientSecret), userTokenCache, null);

        //    var result = await cca.AcquireTokenSilentAsync(scopes, cca.Users.FirstOrDefault(), _azureAdB2COptions.Authority, false);
        //    return result;
        //}

        //private async Task<AuthenticationResult> ObtainTokenFromAzureAdAsync(string signedInUserID, string userObjectID)
        //{
        //    var scopes = _azureAdOptions.ApiScopes.Split(' ');
        //    TokenCache userTokenCache = new MSALSessionCache(signedInUserID, HttpContext).GetMsalCacheInstance();

        //    // Using ADAL.Net, get a bearer token to access the TodoListService
        //    ConfidentialClientApplication cca = new ConfidentialClientApplication(_azureAdOptions.ClientId, _azureAdOptions.Authority, _azureAdOptions.RedirectUri, new ClientCredential(_azureAdOptions.ClientSecret), userTokenCache, null);
        //    var result = await cca.AcquireTokenSilentAsync(scopes , cca.Users.FirstOrDefault(), _azureAdOptions.Authority, false);
        //    return result;
        //}

        [HttpPost]
        public async Task<ActionResult> Index(string item)
        {
            if (ModelState.IsValid)
            {
                //
                // Retrieve the user's tenantID and access token since they are parameters used to call the To Do service.
                //
                
                List<TodoItem> itemList = new List<TodoItem>();
                try
                {
                    AuthenticationResult result = null;
                    using (var domainResolver = new DomainResolver(HttpContext, _azureAdOptions, _azureAdB2COptions))
                    {
                        ViewBag.isB2cUser = domainResolver.isB2cUser;
                        result = await domainResolver.getAccessTokenAsync();
                    }

                    // Forms encode todo item, to POST to the todo list web api.
                    HttpContent content = new StringContent(JsonConvert.SerializeObject(new { Title = item }), System.Text.Encoding.UTF8, "application/json");

                    //
                    // Add the item to user's To Do List.
                    //
                    HttpClient client = new HttpClient();
                    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, _azureAdOptions.TodoListBaseAddress + "/api/todolist");
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
                    request.Content = content;
                    HttpResponseMessage response = await client.SendAsync(request);

                    //
                    // Return the To Do List in the view.
                    //
                    if (response.IsSuccessStatusCode)
                    {
                        return RedirectToAction("Index");
                    }

                    //
                    // If the call failed with access denied, then drop the current access token from the cache, 
                    //     and show the user an error indicating they might need to sign-in again.
                    //
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        return Unauthorized();
                    }
                }
                catch (Exception)
                {
                    //
                    // The user needs to re-authorize.  Show them a message to that effect.
                    //
                    TodoItem newItem = new TodoItem();
                    newItem.Title = "(No items in list)";
                    itemList.Add(newItem);
                    ViewBag.ErrorMessage = "AuthorizationRequired";
                    return View(itemList);
                }
                //
                // If the call failed for any other reason, show the user an error.
                //
                return View("Error");
            }
            return View("Error");
        }

        private ActionResult ProcessUnauthorized(List<TodoItem> itemList, Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext authContext)
        {
            var todoTokens = authContext.TokenCache.ReadItems().Where(a => a.Resource == AzureAdOptions.Settings.TodoListResourceId);
            foreach (Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCacheItem tci in todoTokens)
                authContext.TokenCache.DeleteItem(tci);

            ViewBag.ErrorMessage = "UnexpectedError";
            TodoItem newItem = new TodoItem();
            newItem.Title = "(No items in list)";
            itemList.Add(newItem);
            return View(itemList);
        }
    }
}
