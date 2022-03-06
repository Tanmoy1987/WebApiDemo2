using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreWebApi2 {
    public class JWTAuthHandler {
         private readonly RequestDelegate _next;
         //private readonly IConfiguration _configuration;
         //private readonly JWTSettings _settings;
         public JWTAuthHandler(RequestDelegate next
                     //, IOptions<JWTSettings> settings
                ) 
         {
             _next= next;
             //_settings= settings.Value;
         }
         public async Task Invoke(HttpContext context) {
             IServiceProvider service= context.RequestServices;
             JWTSettings settings= service.GetService<IOptions<JWTSettings>>().Value;

             var tokenHandler= new JwtSecurityTokenHandler();
             string key= settings.key;

             string token= context.Request.Headers["Authorization"];
             if(token == null){
                 context.Response.StatusCode= (int)HttpStatusCode.Forbidden;
                 await context.Response.WriteAsJsonAsync(new {message= "No Token Available"});                
                 //await _next(context);
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
            }
            catch(Exception)
            {
                 context.Response.StatusCode= (int)HttpStatusCode.BadRequest;
                 await context.Response.WriteAsJsonAsync(new {message= "Invalid Token"});   
                 return;
            }

            await _next(context);
         }
    }
}