using System;
using System.Net;
using System.Text;
using System.Security.Claims;
using System.Collections;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.DependencyInjection;
//using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Mvc.Authorization;

namespace AspNetCoreWebApi2 
{
    public class AuthorizeToken : AuthorizeAttribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
           IServiceProvider service= context.HttpContext.RequestServices;
           JWTSettings setting= service.GetService<IOptions<JWTSettings>>().Value; 
           string key= setting.key;
           var tokenHandler= new JwtSecurityTokenHandler();

           string token= context.HttpContext.Request.Headers["Authorization"];
           if(token == null){
               context.Result= new JsonResult(new { message= "No Token Available" });  
               context.HttpContext.Response.StatusCode= (int)HttpStatusCode.Forbidden; 
               return;
           }            
           try
           {
             token= token.Contains("Bearer") ? token.Replace("Bearer","").Trim(): string.Empty;
             tokenHandler.ValidateToken(token, new TokenValidationParameters
              {
                    ValidateAudience= false,
                    ValidateIssuer= false,
                    ValidateLifetime= true,
                    ValidateIssuerSigningKey= true,
                    IssuerSigningKey= new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
              }, out SecurityToken validatedToken);
              
            //   var claims= ((JwtSecurityToken)validatedToken).Claims;
            //   context.HttpContext.User= new ClaimsPrincipal(new ClaimsIdentity(claims));
           }
            catch(Exception)
            {
                context.Result= new JsonResult(new { message= "Invalid Token" }); 
                context.HttpContext.Response.StatusCode= (int)HttpStatusCode.BadRequest;
                return;
            }
        }
    } 
}