using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;

namespace TodoListService
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication()
            .AddJwtBearer("AzureAd", options =>
            {
                options.Authority = $"{Configuration["AzureAd:Instance"]}{Configuration["AzureAd:TenantId"]}/v2.0/";
                options.Audience = Configuration["AzureAd:ClientId"];
                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters() { ValidateIssuer = true };
            })
            .AddJwtBearer("AzureAdB2C", options =>
            {
                options.Authority = $"{Configuration["AzureAdB2C:Instance"]}/tfp/{Configuration["AzureAdB2C:Tenant"]}/{Configuration["AzureAdB2C:Policy"]}/v2.0/";
                options.Audience = Configuration["AzureAdB2C:ClientId"];
                options.RequireHttpsMetadata = false;
            });
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseAuthentication();
            app.UseMvc();
        }

        //Development Purpose... Donot include in Authentication Event Handler
        //private Task AuthenticationFailed(AuthenticationFailedContext arg)
        //{
        //    // For debugging purposes only!
        //    var s = $"AuthenticationFailed: {arg.Exception.Message}";
        //    arg.Response.ContentLength = s.Length;
        //    arg.Response.Body.Write(Encoding.UTF8.GetBytes(s), 0, s.Length);
        //    return Task.FromResult(0);
        //}
    }
}
