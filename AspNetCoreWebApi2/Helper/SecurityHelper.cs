using System;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

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
              , new Claim(ClaimTypes.DateOfBirth, new DateTime(1987, 7, 13).ToString())
            };

            var token= new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: tokenClaims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: new SigningCredentials(
                      new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_settings.key))
                    , SecurityAlgorithms.HmacSha256
                )
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public interface IJWTAuthToken {
        string Generate(string name);
    }
}