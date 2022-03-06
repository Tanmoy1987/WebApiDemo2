using System;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;

namespace AspNetCoreWebApi2 {
    public class DefaultAuthHandler:  AuthenticationHandler<AuthenticationSchemeOptions> {
        public DefaultAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) 
                  : base(options, logger, encoder, clock) {}
        protected async override Task<AuthenticateResult> HandleAuthenticateAsync(){
            return await Task.Run(() => Validate());
        }

        private AuthenticateResult Validate() {
            if(string.IsNullOrEmpty(Request.Headers["Authorization"]))
               return AuthenticateResult.Fail("no valid token");
            Claim[] claim= new Claim[] {};   
            return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claim)), "default"));
        }
    }
}