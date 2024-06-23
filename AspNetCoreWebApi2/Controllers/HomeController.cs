using System;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;

namespace AspNetCoreWebApi2.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class HomeController : ControllerBase
	{
		private readonly ILogger _logger;
		private IJWTAuthToken _jwtToken;

		public HomeController(ILogger logger
							, IJWTAuthToken token)
		{
			_logger = logger;
			_jwtToken= token;
		}

		[HttpGet]
		//using custom Authorize attribute
		[AuthorizeToken]
		//Adding Middleware filter attribute
		//[MiddlewareFilter(typeof(JWTMiddlewareBuilder))]
		public IActionResult Get()
		{
		   _logger.LogInformation("GET Method call...");
		   return StatusCode((int)HttpStatusCode.OK, new { value= "Tanmoy"});
		}

		[HttpGet]
		[Route("Adult")]
		[Authorize(Policy="Atleast18")]
		// [AuthorizeToken]
		public IActionResult GetAdultContent(){
			_logger.LogInformation("GET Method call...AdultContent");
			return StatusCode((int)HttpStatusCode.OK, "Adult Content...");
		}
		[HttpGet]
		[Route("Entertainment")]
		[TokenAuthenticator]
		public IActionResult GetEntertainmentContent() {
			return StatusCode((int)HttpStatusCode.OK, "Entertainment Content...");
		}
		[HttpPost]
		public IActionResult Post([FromBody] string name){
			return StatusCode((int)HttpStatusCode.OK, _jwtToken.Generate(name));
		}
		
		[HttpPost]
		[Route("Token")]
		public IActionResult Post([FromBody] UserClaimPrincipal claimPrincipals) {
			return StatusCode((int)HttpStatusCode.OK, _jwtToken.GenerateAsymmetricJwt(claimPrincipals));
		}
	}
}
