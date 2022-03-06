using Microsoft.AspNetCore.Builder;

namespace AspNetCoreWebApi2 {
    public class JWTMiddlewareBuilder
    {
        public void Configure(IApplicationBuilder builder){
            builder.UseMiddleware<JWTAuthHandler>();
        }
    }
}