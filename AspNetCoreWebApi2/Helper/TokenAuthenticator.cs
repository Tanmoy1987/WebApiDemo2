using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.Intrinsics.Arm;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreWebApi2
{
	public class TokenAuthenticator : ActionFilterAttribute, IActionFilter
	{
		public override void OnActionExecuted(ActionExecutedContext context)
		{
			//throw new System.NotImplementedException();
		}

		public override void OnActionExecuting(ActionExecutingContext context) {
		   IServiceProvider service= context.HttpContext.RequestServices;
		   JWTSettings setting= service.GetService<IOptions<JWTSettings>>().Value; 
		   string publicKey= Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), setting.PublicKey);
		   JwtSecurityTokenHandler tokenHandler= new JwtSecurityTokenHandler();

		   string token= context.HttpContext.Request.Headers["Authorization"];
		   if(token == null){
			   context.Result= new JsonResult(new { message= "No Token Available" });  
			   context.HttpContext.Response.StatusCode= (int)HttpStatusCode.Forbidden; 
			   return;
		   }
		   token= token.Contains("Bearer ") ? token.Replace("Bearer ","") : token;
		   var jwt= ValidateJWT(token, publicKey);
		   if(jwt is null) {
			 context.Result= new JsonResult(new { message= "invalid token" });
			 context.HttpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;
			 return;
		   } 
		   return;
		}
		
		private JwtSecurityToken ValidateJWT(string token, string publicKey) {
		   JwtSecurityToken jwt= new JwtSecurityToken(token);
		   SHA256 sHA256= SHA256.Create();
		   byte[] hash= sHA256.ComputeHash(Encoding.UTF8.GetBytes($"{jwt.RawHeader}.{jwt.RawPayload}"));
		   using DigitalSignature ds= new DigitalSignature(2048, "SHA256");
		   ds.ImportPublicKeyInBlob(publicKey);
		   if(ds.VerifySignature(hash, Base64UrlEncoder.DecodeBytes(jwt.RawSignature))) {
			  if(DateTime.Parse(GetClaimValue(jwt, "exp")) >= DateTime.Now 
				  && DateTime.Parse(GetClaimValue(jwt, "nbf")) <= DateTime.Now 
				  && GetClaimValue(jwt, "iss").Contains("http://example.com") 
				  && GetClaimValue(jwt, "aud").Contains("http://myportal.com")
			   )
			  return jwt;
			}
			return null;
		}
		
		private string GetClaimValue(JwtSecurityToken jwt, string claimType) {
			Claim claim= jwt.Claims.FirstOrDefault(y => y.Type == claimType);
			return claim is null ? string.Empty : claim.Value;
		}
	}
}