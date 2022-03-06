using Microsoft.AspNetCore.Authorization;
namespace AspNetCoreWebApi2 {
    public class MinimumAgeRequirement : IAuthorizationRequirement {
        public MinimumAgeRequirement(){           
        }
    }
}