using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Web_API_JWT.Formats;
using Web_API_JWT.Providers;

namespace Web_API_JWT
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration config = new HttpConfiguration();

            // Web API routes
            config.MapHttpAttributeRoutes();

            ConfigureOAuth(app);

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);

            app.UseWebApi(config);

        }

        public void ConfigureOAuth(IAppBuilder app)
        {

            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                //For Dev enviroment only (on production should be AllowInsecureHttp = false)
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/oauth2/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),
                //We have specified the implementation on how to validate the client and Resource owner user credentials in a custom class named "CustomOAuthProvider".
                Provider = new CustomOAuthProvider(),
                //We have specified the implementation on how to generate the access token using JWT formats, 
                //this custom class named "CustomJwtFormat" will be responsible for generating JWT instead of default access token 
                //Note: that both are using bearer scheme.
                AccessTokenFormat = new CustomJwtFormat("http://localhost:10077/")
                
            };

            // OAuth 2.0 Bearer Access Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);

        }
    }
}