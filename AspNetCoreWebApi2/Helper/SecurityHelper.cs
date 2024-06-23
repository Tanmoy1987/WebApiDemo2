using System;
using System.Security.Claims;
using System.Globalization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Reflection;

namespace AspNetCoreWebApi2
{
	public class JWTAuthToken : IJWTAuthToken {
		private readonly JWTSettings _settings;
		public JWTAuthToken(IOptions<JWTSettings> settings) {
			_settings= settings.Value;
		}
		public string Generate(string name) {
			var tokenClaims= new Claim[] {
				//new Claim(ClaimTypes.Name, name), new Claim(ClaimTypes.Role, "Contractor")
				new Claim(ClaimTypes.Name, name)
			  , new Claim(ClaimTypes.Role, "Administrator")
			  , new Claim(ClaimTypes.DateOfBirth, new DateTime(1987, 07, 13).ToString(new CultureInfo("en-US")))
			};

			var token= new JwtSecurityToken(
				issuer: null,
				audience: null,
				claims: tokenClaims,
				notBefore: DateTime.Now,
				expires: DateTime.Now.AddMinutes(10),
				signingCredentials: new SigningCredentials(
					  new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_settings.key))
					, SecurityAlgorithms.HmacSha256
				)
			);

			return new JwtSecurityTokenHandler().WriteToken(token);
		}
		public string GenerateAsymmetricJwt(UserClaimPrincipal claimPrincipal) 
		{
			string privateKeyPath= Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), _settings.PrivateKey);
			List<Claim> claims= BuildClaimList(claimPrincipal);
			JwtSecurityTokenHandler tokenHandler= new JwtSecurityTokenHandler();
			
			JwtHeader header= new JwtHeader();
			header.Add("alg", "RS256");
			header.Add("typ", "JWT");
			string jwtHeader= header.Base64UrlEncode();
			
			JwtPayload payload= new JwtPayload();
			payload.Add("iss", "http://example.com");
			payload.Add("aud", "http://myportal.com");
			payload.Add("iat", DateTime.Now);
			payload.Add("nbf", DateTime.Now.AddSeconds(30));
			payload.Add("exp", DateTime.Now.AddMinutes(10));
			claims.ForEach(y => payload.Add(y.Type, y.Value));
			string jwtPayload= payload.Base64UrlEncode();
			
			using DigitalSignature ds= new DigitalSignature(2048, "SHA256");
			ds.ImportPrivateKeyInBlob(privateKeyPath);
			SHA256 sha256= SHA256.Create();
			byte[] jwtHashedPayload= sha256.ComputeHash(Encoding.UTF8.GetBytes($"{jwtHeader}.{jwtPayload}"));
			byte[] jwtSignature	= ds.SignData(jwtHashedPayload); 
			return $"{jwtHeader}.{jwtPayload}.{Base64UrlEncoder.Encode(jwtSignature)}";
		}
		private List<Claim> BuildClaimList(UserClaimPrincipal claimPrincipal)	
		{
			return new List<Claim>() 
			{
				new Claim("username", claimPrincipal.UserName),
				new Claim("firstname", claimPrincipal.FirstName),
				new Claim("lastname", claimPrincipal.LastName),
				new Claim("email", claimPrincipal.Email)
			};
		}
	}
	public interface IJWTAuthToken {
		string Generate(string name);
		string GenerateAsymmetricJwt(UserClaimPrincipal claimPrincipal);
	}
}