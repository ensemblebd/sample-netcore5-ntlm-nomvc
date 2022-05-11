using System;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.SpaServices.Webpack;
using Microsoft.Extensions.Logging;
using WebApp.Models;
using WebApp.Middleware;
using WebApp.Services;
using WebApp.Services.Registration;

namespace WebApp {
	public class Startup {
		private IConfiguration _configuration;
		private IWebHostEnvironment _env;
		internal static String ROOT_PATH;
		internal static String WEB_PATH;
		internal static String BIN_PATH;

		public Startup(IConfiguration configuration, IWebHostEnvironment env) {
			_configuration = configuration;
			_env = env;

			ROOT_PATH = env.ContentRootPath;
			WEB_PATH = env.WebRootPath;
			BIN_PATH = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

			var cwd = Directory.GetCurrentDirectory();
			NLog.LogManager.LoadConfiguration(String.Concat(cwd, "/nlog.config"));
		}

		public void ConfigureServices(IServiceCollection services) {
			Program._bootStatus.Update(BOOT_CORE_STATE.REGISTRATION, BOOT_STATE_TYPE.PRE);

			services.AddSingleton<IConfiguration>(_configuration);
			services.ConfigureLoggerService();

			// allow everything to access the user principal if needed.
			services.AddTransient<IPrincipal>(provider => {
				var http = provider.GetService<IHttpContextAccessor>();
				return http.HttpContext.User;
			});
			services.AddTransient<IActiveDirectory, ActiveDirectory>();
			services.AddScoped<Authentication>();

			// add identity jwt token bearer auth for microsoft's mvc chain.
			services.AddAuthentication(o => {
				o.DefaultAuthenticateScheme = "smart";
				o.DefaultSignInScheme = "smart";
				//o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
			})
			.AddPolicyScheme("smart", "Switch between bearer and ntlm", options => {
				options.ForwardDefaultSelector = context => {
					var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();

					// preferrentially use the cookie/local-storage based token. 
					if (authHeader?.ToLower().StartsWith("bearer ") == true) {
						return JwtBearerDefaults.AuthenticationScheme;
					}
					// otherwise, presume the request is pushing through kerberos/ntlm credentials. 
					return Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.Negotiate;
				};
			})
			.AddJwtBearer(o => { // we shall use Bearer authentication, which is FORCED into the browser's request system via websocket request middleware on frontend. It will send bearer auth with every request.
				o.TokenValidationParameters = ormConfig.GetJWTTokenValidationParameters();
			})
			.AddNegotiate(); // allow kerberos/ntlm negotiation & challenges.

			Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
			// Microsoft IDentity requries cookie storage to keep the auth details. 
			// this must occur PRIOR to signalR registration. Without this, IPrincipal does not contain the claims upon login. 'Cause Microsoft is "awesome" and stuff or whatever? Yea that. cool.
			// we are using Bearer auth anyway, but this is still apparently requried to hook everything up.
			services.ConfigureApplicationCookie(o => {
				o.AccessDeniedPath = "/";
				o.Cookie.Name = "WebApp";
				o.Cookie.HttpOnly = true;
				o.ExpireTimeSpan = TimeSpan.FromMinutes(30); // todo: add to configuration variable??
				o.LoginPath = "/";
				o.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
				o.SlidingExpiration = true; // refresh timeout upon page / action executed.
			});


			services.AddMemoryCache();
			services.AddSignalR(); // SPA 
			
			
			services.AddCors(options => {
#if RELEASE
				options.AddPolicy("CorsPolicy",
				builder => builder
					.AllowAnyOrigin() // todo: restrict this
					.AllowAnyMethod()
					.AllowAnyHeader()
					//.AllowCredentials() // cannot have both credentials and allow any origin.
				);
#else
				options.AddPolicy("CorsPolicy",
				builder => builder
					.AllowAnyOrigin()
					.AllowAnyMethod()
					.AllowAnyHeader()
					//.AllowCredentials() // cannot have both credentials and allow any origin.
				);
#endif
			});


			// add mvc specifically for our custom "api" lib dll, as well for swagger ui.
			services
				.AddMvc()
				.AddNewtonsoftJson() // api lib technically contains the dll ref for this (ms.netcore.mvc.newton), but it is dependent upon mvc callback (here). Can't register directly onto services, and we don't want to register mvc twice. Otherwise this line would be in it's PROPER home, the api lib project.
				.SetCompatibilityVersion(Microsoft.AspNetCore.Mvc.CompatibilityVersion.Version_3_0)
				.AddApplicationPart(typeof(API.Bootstrap).Assembly) // external library reference
				.AddControllersAsServices();

			// we are using a seperate library to manage the api, for cleanliness. Register it w/ swagger, and apply an authorization filter to prevent unauthorized access by way of MS Identity tokens.
			services.AddExternalAPILib<SwaggerAuthorizationFilter>();

			// use bearer authorization for all exposed services. Since we use CookieAuth for microsoft Identity (under the hood), this only truly affects the swagger api.
			services.AddAuthorization(auth => {
				auth.AddPolicy("Bearer", new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme).RequireAuthenticatedUser().Build());
			});

			// quartz job scheduler w/ DI injection
			services.AddBackgroundJobs();
		}
		
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IServiceScopeFactory scopeFactory, ILoggerManager logger) {
			logger.LogInfo("Configure() executed..");

			if (env.IsDevelopment()) {
				app.UseDeveloperExceptionPage();
				app.UseDatabaseErrorPage();
			}

			// since we use react on frontend, we will be provisioning STATIC files (ie html).
			app.UseStaticFiles();


			app.UseAuthentication(); // will attach Identity resultants to HttpContext.Current.user. Must be called prior to AuthServer middleware (aka "AuthenticateAsync" internal call)
			//app.UseAuthorization(); // not needed. middleware for mvc. very particular on order of ops here. may need moved.

			
			// this MUST occur after the "UseAuthentication" middleware just above. 
			app.UseMiddleware<NTLMAuthMiddleware>();


			// Runs path matching on url. An endpoint is selected and set on the HttpContext if a match is found. 
			app.UseRouting();

			// register routing decisions, in order of priority.
			app.UseEndpoints(endpoints => {
				// todo: remove these two - they serve no purpose for our project
				endpoints.MapControllers();
				endpoints.MapRazorPages();
				// add our custom api library...
				API.Bootstrap.OnConfigure(endpoints, ROOT_PATH);
			});


			// Load swagger ui for easy developer usage of api..
			var UseSwagger = env.IsDevelopment();
			if (UseSwagger) {
				app
					.UseSwagger()
					.UseSwaggerUI(c => {
						c.SwaggerEndpoint("/swagger/v1/swagger.json", "WebApp API");
						c.OAuthClientId(ormConfig.Jwt.ProviderID);
						c.OAuthClientSecret(ormConfig.Jwt.ProviderSecret);
						c.OAuthRealm(ormConfig.Jwt.Realm);
						c.OAuthAppName("WebApp API");
					});
			}


			logger.LogInfo("System has been configured. Running now:");
			
			app.Run(async (context) => {
				var uri = context.Request.Path.ToUriComponent();
				if (uri.EndsWith(".map"))
					return;

				// http://localhost:51021/dist/hot/main.655d7e8ba4d21f447fbb.hot-update.json
				else if (env.IsDevelopment() && uri.StartsWith("/dist/")) {
					var the_file = Path.Combine(WEB_PATH, uri.TrimStart('/').Replace("/", "\\"));
					if (File.Exists(the_file)) {
						using (var reader = new StreamReader(File.OpenRead(the_file)))
							await context.Response.WriteAsync(reader.ReadToEnd());
					}
				}
				
				else {
					// by default all requests will return the root html file which is the react SPA..
					using (var reader = new StreamReader(File.OpenRead("wwwroot/index.html")))
						await context.Response.WriteAsync(reader.ReadToEnd());
				}
			});
		}

	}
	
}
