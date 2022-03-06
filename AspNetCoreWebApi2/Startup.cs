using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AspNetCoreWebApi2
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "AspNetCoreWebApi2", Version = "v1" });
                c.AddSecurityDefinition("JWT", new OpenApiSecurityScheme
                {
                    Name="Authorization",
                    Type= SecuritySchemeType.ApiKey,
                    Scheme="bearer",
                    In= ParameterLocation.Header,
                    Description = "JWT header using the Bearer scheme."  
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement  
                {  
                    {  new OpenApiSecurityScheme  {  Reference = new OpenApiReference  {  
                                    Type = ReferenceType.SecurityScheme,  
                                    Id = "bearer"  
                            }  
                        },  new string[] {}  
                    }  
                });
            });

            //services.AddAuthentication("default").AddScheme<AuthenticationSchemeOptions, DefaultAuthHandler>("default", null);
            // To implement JWT Authentication and Claim-Policy Based Authorization.
            
            services.AddAuthentication(option => {
                option.DefaultAuthenticateScheme= JwtBearerDefaults.AuthenticationScheme;
                option.DefaultChallengeScheme= JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(tokn => {
                tokn.RequireHttpsMetadata = false;
                tokn.SaveToken= true;
                tokn.TokenValidationParameters= new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateAudience= false,
                    ValidateIssuer= false,
                    ValidateLifetime= true,
                    ValidateIssuerSigningKey= true,
                    IssuerSigningKey= new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration.GetSection("JWT:Key").Value))
                };
            });

            services.AddAuthorization(o => o.AddPolicy("Atleast18", policy => policy.Requirements.Add(new MinimumAgeRequirement())));

            services.Configure<JWTSettings>(Configuration.GetSection("Jwt"));
            ILoggerFactory factory= LoggerFactory.Create(builder => builder.AddConsole());
            services.AddSingleton(factory.CreateLogger("log"));
            services.AddSingleton<IJWTAuthToken, JWTAuthToken>();    
            services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();         
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseSwagger();
            app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "AspNetCoreWebApi2 v1"));
            //app.UseHttpsRedirection();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization(); 

            //comment out When, we don't want to invoke the middleware for each request.
            //app.UseJWTAuthHandlerMiddleware();    

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });            
        }
    }
}
