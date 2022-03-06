using System;
using Microsoft.AspNetCore.Builder;

namespace AspNetCoreWebApi2 {
    public static class JWTAuthHandlerExtension {
        public static IApplicationBuilder UseJWTAuthHandlerMiddleware(this IApplicationBuilder builder){
            return builder.UseMiddleware<JWTAuthHandler>();
        } 
    }
}