using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Web_API_JWT.Domain;
using Web_API_JWT.EntityFramework;

namespace Web_API_JWT.Providers
{
    public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        private readonly hPayDomain _hPayDomain;
        private string _userFullName;
        private string _emailId;

        public CustomOAuthProvider()
        {
            _hPayDomain = new hPayDomain();
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            string clientId = string.Empty;
            string clientSecret = string.Empty;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                context.SetError("invalid_clientId", "client_Id is not set");
                return Task.FromResult<object>(null);
            }
            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext oAuthGrantResourceOwnerCredentialsContext)
        {
            User hPayUser = _hPayDomain.AuthenticateUser(oAuthGrantResourceOwnerCredentialsContext.UserName, oAuthGrantResourceOwnerCredentialsContext.Password);

           


            if (hPayUser != null)
            {
                _userFullName = hPayUser.UserFirstName + " " + hPayUser.UserLastName;
                _emailId = hPayUser.EmailId;

                IList<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Role, "provider"),
                    new Claim(ClaimTypes.Name, _userFullName),
                    new Claim(Constants.Username, _emailId)
                };

                //Claims will be encrypted in token, so they will only be accessed from resource(i.e. client) server
                ClaimsIdentity identity = new ClaimsIdentity(claims, oAuthGrantResourceOwnerCredentialsContext.Options.AuthenticationType);

                IDictionary<string, string> authenticationPropertiesDictionary = new Dictionary<string, string>();
                authenticationPropertiesDictionary.Add(Constants.Audience, oAuthGrantResourceOwnerCredentialsContext.ClientId ?? string.Empty);
                authenticationPropertiesDictionary.Add(Constants.Username, oAuthGrantResourceOwnerCredentialsContext.UserName);
                authenticationPropertiesDictionary.Add(Constants.UserFullName, hPayUser.UserFirstName + " " + hPayUser.UserLastName);


                //Adds authentication properties, if you want your client to be able to read extended properties
                AuthenticationProperties authenticationProperties = new AuthenticationProperties(authenticationPropertiesDictionary);

                AuthenticationTicket ticket = new AuthenticationTicket(identity, authenticationProperties);

                //The token generation happens behind the scenes when we call  "oAuthGrantResourceOwnerCredentialsContext.Validated(ticket);"
                oAuthGrantResourceOwnerCredentialsContext.Validated(ticket);

            }
            else
            {
                oAuthGrantResourceOwnerCredentialsContext.SetError("invalid_grant", "The user name or password is incorrect");
                
            }

           
        }

        // Add additional parameter to return with response
        public override Task TokenEndpoint(OAuthTokenEndpointContext oAuthTokenEndpointContext)
        {
            // Add authentication properties via iterate which is added as a part of GrantResourceOwnerCredentials()
            foreach (KeyValuePair<string, string> property in oAuthTokenEndpointContext.Properties.Dictionary)
            {
                oAuthTokenEndpointContext.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            oAuthTokenEndpointContext.AdditionalResponseParameters.Add("TestParam1", "Value1");
            oAuthTokenEndpointContext.AdditionalResponseParameters.Add("TestParam2", "Value2");

            return Task.FromResult<object>(null);
        }
    }
}