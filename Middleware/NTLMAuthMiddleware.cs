using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using WebApp.Models;
using WebApp.Services;
using WebApp.Services.AD;
using WebApp.Extensions;
using WebApp.Models;

namespace WebApp.Middleware {
	public class NTLMAuthMiddleware {
		internal static HelperLib.Crpto.RSAKeys rsaKeys = new EGAspNetCore.Crpto.RSAKeys("WebAppSecretKeyHereMustBe20CharsLongAtLeast");
		ILogger log;
		RequestDelegate next;
		IGlobalBootStatus bootStatus;

		public NTLMAuthMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, IGlobalBootStatus bootStatus) {
			log = loggerFactory.CreateLogger<NTLMAuthMiddleware>();
			this.next = next;
			this.bootStatus = bootStatus;
		}

		private static bool pathMatch(HttpContext context, string path) => context.Request.Path.Equals(path, StringComparison.Ordinal);
		public static bool matchTargetPaths(HttpContext context) {
			var settings = context.RequestServices.GetRequiredService<AppIdentity>();
			return pathMatch(context, settings.AuthPaths.NTLM); //  "/auth" for instance
		}


		public async Task InvokeAsync(HttpContext context, ISystemHooks m_hooks) {
			if (!bootStatus.IsBooted) {
				await next(context);
			}
			else {
				var _config = context.RequestServices.GetRequiredService<IOptionsSnapshot<AppIdentity>>();
				var config_identity = _config.Value;
				// check for ad auth request.
				if (pathMatch(context, config_identity.AuthPaths.NTLM)) {
					var response = new AuthResponseDetails();

					// if system hasn't booted, we can't access AD, as it relies on Cache, which relies on Database. all of which aren't ready yet.
					// so we obtain it on-the-fly when sys is ready... Since middleware runs on EVERY single request.
					using (var m_ad = context.RequestServices.GetRequiredService<IActiveDirectory>()) {
						if (!context.Request.Method.Equals("GET") && !context.Request.Method.Equals("POST")) {
							// cors event?
							context.Response.StatusCode = 200;
							return;
						}
						else {
							log.LogInformation($"User is attempting NTLM auth");
							try {
								response = await LoginNTLM(context, m_hooks, m_ad, config_identity);
							}
							catch (Exception ex) {
								response.FailWith(ex.Message);
							}
							if (response.tokenDetails != null && (response.tokenDetails.IsNTLMPhase1 || response.tokenDetails.IsNTLMPhase2)) {
								// body and code already written. Browser will attempt to negotiate immediately.
								if (response.tokenDetails.IsNTLMPhase2) {
									if (!context.Response.HasStarted) {
										context.Response.StatusCode = 200;
										context.Response.ContentType = "application/json";
									}
									await context.Response.WriteAsync(JsonConvert.SerializeObject(response));
								}
								return;
							}
						}

						if (!context.Response.HasStarted) {
							if (response.Success) {
								context.Response.StatusCode = 200;
							}
							else {
								context.Response.StatusCode = 400;
							}
						}
						await context.Response.WriteAsync(JsonConvert.SerializeObject(response));
						return;
					}

				}
				else {
					await next(context);
				}
			}
		}


		// useful source: https://stackoverflow.com/questions/68916846/how-to-use-windows-authentication-on-asp-net-core-subpath-only
		// and: https://stackoverflow.com/questions/50400393/asp-net-core-windows-authentication-not-working-in-iis
		// and: https://stackoverflow.com/questions/49682644/asp-net-core-2-0-ldap-active-directory-authentication/49742910#49742910
		// another: https://www.seeleycoder.com/blog/windows-authentication-with-react/
		// scheme ref: https://docs.microsoft.com/en-us/dotnet/framework/wcf/feature-details/understanding-http-authentication#:~:text=NTLM%20uses%20Windows%20credentials%20to,between%20the%20client%20and%20server.&text=Negotiate%20authentication%20automatically%20selects%20between,NTLM%20authentication%2C%20depending%20on%20availability.
		private async Task<AuthResponseDetails> LoginNTLM(HttpContext context, ISystemHooks m_hooks, IActiveDirectory m_ad, AppIdentity config_identity) {
			var response = new AuthResponseDetails();
			AuthenticateResult windowsAuth = null;

			try {
				windowsAuth = await context.AuthenticateAsync(Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.Negotiate);
			}
			catch (Exception ex) {
				// this is fatal. something deeply wrong server-side. 
				response.FailWith("Unable to use Windows Auth: " + ex.Message);
				return response;
			}
			if (!windowsAuth.Succeeded) {
				// negotiation is required. It will always happen first time the user attempts to windows auth. 
				// secondary request from client to same path (here), will include claims of the current windows users and thus succeed (proceed below).
				await context.ChallengeAsync(Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.Negotiate);
				// first phase of NTLM auth is to force the browser to execute a kerberos negotiation attempt. Phase 1 of 3.
				response.tokenDetails = new ResponseTokenDetails() { IsNTLMPhase1 = true };
				return response;
			}
			else {
				// phase 2 of the authentication follows -- whereby the browser has provided us with valid NTLM username info from the windows machine due to security allow list of the target website.
				// so we send back a token that basically says "this middleware authorizes the ntlm_username to login". 
				// a react VM will handle the phase 3 sign in, which touches the database. We issue it a token that serverside can later verify (aka phase3)
				// but user is technically 100% auth'd at this point via AD.

				var ntlm_username = string.Join("\\", windowsAuth.Principal.Claims.FirstOrDefault(c => c.Type.EndsWith("name")).Value.Split("\\").Skip(1));
				var matched_groups = new List<string>();
				var allow_registration = false;
				ADUser ad_user = null;

				if (String.IsNullOrEmpty(ntlm_username)) {
					response.FailWith("Invalid account provided.");
					return response;
				}
				else {
					// at this point we need to match the user to AD. 
					// if we are on dev, there is no AD system, but we do have an AD test enviro, specifically for testing this scenario. 
					// .. so we must use a config switch to control the logic depending on the deployment.
					if (config_identity.AD.MatchUserNTLM) {
						// in this case we let AD determine whether the person can register for first time.
						// todo: consider using the SID's in database storage or by way of AD lookup in a memory cache. We can speed the operation up by avoiding communicating with AD at all. AT ALL period. Because if we have the SID's from kerberos/ntlm windows locally and we validated them previously, then we know precisely whether or not the user logging in via windows has access to a group.

						try {
							ad_user = await m_ad.GetUser(ntlm_username);
						}
						catch(Exception ex) {
							log.LogError(ex, "Failed to communicate with AD server.");
							response.FailWith("Could not communicate with AD server.");
							return response;
						}
						if (ad_user==null) {
							response.FailWith("Could not locate your account in AD.");
							return response;
						}

						allow_registration = true;
					}
					else {
						// in this case we presume the user is valid and can login. we proceed below. Either the account exists in database or it doesn't.
					}
				}

				// with the user validated by AD, we can proceed to login.
				// however middleware using dbcontext is unstable (entity framework scope issue). So we will defer to the client to send secondary request using the VM from react's websocket connection (phase 3) using a validated token below, to use a stable channel for entity framework via DI injection.
				var ip = context.GetIP();
				response.tokenDetails = new ResponseTokenDetails() {
					IsNTLMPhase2 = true,
					ValidatedNTLMUsername = ntlm_username,
					NTLMToken = Cryptography.EncryptDataToBase64(JsonConvert.SerializeObject(new NTLMTokenPhase1() {
						pk = config_identity.Jwt.Key,
						u = ntlm_username,
						i = ip
					}), rsaKeys)
				};
			}

			return response;
		}


	}
}
