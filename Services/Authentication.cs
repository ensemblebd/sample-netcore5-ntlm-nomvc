using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using WebApp.Models;
using WebApp.Services;
using WebApp.Services.AD;
using WebApp.Extensions;

namespace WebApp.Services {

	public class Authentication : IDisposable {
		static bool HARDCODED_INCLUDE_ROLES_CLAIMS = true;
		static bool HARDCODED_INCLUDE_GROUPS_CLAIMS = true;
		static bool HARDCODED_INCLUDE_MICROSOFT_CLAIMS = false;

		ILogger log;
		AppIdentity config_identity;
		TokenProviderOptions token_options;
		TokenValidationParameters tokenValidationParameters;
		HttpContext context;
		IGlobalBootStatus bootStatus;
		IActiveDirectory m_ad;
		ISystemHooks m_hooks;
		IDBMemoryCache m_cache;
		IGroupManager m_groups;
		ApplicationSignInManager m_signIn;
		ApplicationUserManager m_users;

		public Authentication(IOptionsSnapshot<AppIdentity> _config_identity, ILoggerFactory loggerFactory, IHttpContextAccessor http, IGlobalBootStatus bootStatus, IActiveDirectory m_ad, ISystemHooks m_hooks, IDBMemoryCache m_cache, ApplicationUserManager m_users, IGroupManager m_groups, ApplicationSignInManager m_signIn) {
			log = loggerFactory.CreateLogger<Authentication>();
			context = http.HttpContext;
			this.config_identity = _config_identity.Value;
			this.bootStatus = bootStatus;
			this.m_ad = m_ad;
			this.m_hooks = m_hooks;
			this.m_cache = m_cache;
			this.m_groups = m_groups;
			this.m_signIn = m_signIn;
			this.m_users = m_users;


			// warning, key length MUST be large enough for HS256. 16 chars + 
			// ---> System.ArgumentOutOfRangeException in System.Private.CoreLib.dll :: IDX10603: Decryption failed. Keys tried: HS256
			var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(config_identity.Jwt.Key));
			token_options = new TokenProviderOptions {
				Audience = config_identity.Jwt.Audience,
				Issuer = config_identity.Jwt.Issuer,
				Expiration = TimeSpan.FromMinutes(Math.Clamp(config_identity.Jwt.ExpireMinutes, 1, 10080)), // max 1 week.
				SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
			};
			tokenValidationParameters = config_identity.GetJWTTokenValidationParameters();
		}
		public void Dispose() {

		}


		private async Task<bool> RefreshTokenWeb(AuthResponseDetails response, System.Security.Principal.IIdentity identity) {
			IApplicationUser user = null;
			var users = m_cache.Users.Where(x => x.UserName.ToLower() == identity.Name.ToLower());
			if (users.Any()) {
				user = users.First();
			}

			if (user == null || user.Id < 1) {
				response.FailWith("Unable to locate user by token.");
				return false;
			}

			var authDetails = AuthenticatedResponse(context, m_cache, user, null, out SecurityToken token);
			response.RespondWith(authDetails);
			return true;
		}
		public async Task<AuthResponseDetails> RefreshToken(string token) {
			var response = new AuthResponseDetails();
			ClaimsPrincipal principal = null;
			var validatedToken = loadTokenPrincipalFromRequest(out principal, token);

			if (validatedToken != null && principal != null && principal.Identity != null && principal.Identity.IsAuthenticated && !String.IsNullOrEmpty(principal.Identity.Name)) {
				log.LogInformation($"User is refreshing their token:  {principal.Identity.Name}");

				var success = await RefreshTokenWeb(response, principal.Identity);
				return response;
			}

			response.FailWith("Bad request.");
			return response;
		}


		private bool ValidatePhase1NTLM(string desiredUser, string base64) {
			var rawTokenInfo = Cryptography.DecryptData(base64.Base64ToBinary(), server.Middleware.NTLMAuthMiddleware.rsaKeys);
			var tokenInfo = JsonConvert.DeserializeObject<NTLMTokenPhase1>(rawTokenInfo);

			var providerMatched = (tokenInfo.pk == config_identity.Jwt.Key);
			var userMatched = (desiredUser == tokenInfo.u);
			var ipMatched = (context.GetIP() == tokenInfo.i);

			return (providerMatched /* && ipMatched && userMatched */); // disabled extra protection for now, for safety. Need to test. and think about it. What if user's ip changes (vpn etc)? etc. For now if provider matches, then we're good.
		}
		public async Task<AuthResponseDetails> NTLMFollowup(string ntlm_username, string authorizedTokenFromMiddleware) {
			var response = new AuthResponseDetails();
			var isValid = ValidatePhase1NTLM(ntlm_username, authorizedTokenFromMiddleware);
			if (!isValid) {
				log.LogWarning($"An invalid token was attempted for NTLM authentication(user: {ntlm_username}, ip: {context.GetIP()}): " + authorizedTokenFromMiddleware);
			}

			ADUser ad_user = null;
			try {
				ad_user = await m_ad.GetUser(ntlm_username);
			}catch(Exception ex) {
				log.LogError(ex, "Failed to communicate with AD to validate username.");
				response.FailWith("Could not communicate with AD server");
			}

			if (ad_user != null) {
				var allow_registration = true;

				IApplicationUser user = null;
				var users = m_cache.Users.Where(x => x.UserName.ToLower() == ntlm_username.ToLower());
				if (users.Any()) {
					user = users.First();
					// user already existed. Let's sync their groups.
					await ADSyncGroups(m_cache, m_groups, user, ad_user, config_identity.AD.GroupForceCascade, config_identity.AD.GroupForceViewerMinimum);
					// and their default information as well (name change, got married, etc):
					var db_user = await m_users.FindByIdAsync(user.Id);
					await ADSyncUserInfo(m_users, db_user, ad_user);
				}
				else {
					// if the user doesn't exist, and AD matched them, we should auto-register their new account
					if (allow_registration && ad_user != null) {
						user = await ADRegisterUser(response, ad_user);
						if (user == null) {
							// response already written. just break out.
							return response;
						}
					}
				}

				if (user != null) {
					await m_hooks.onUserLoginAsync(context.RequestServices, user, ad_user.Principal);

					var authDetails = AuthenticatedResponse(context, m_cache, user, null, out SecurityToken token);
					response.RespondWith(authDetails);
				}
				else {
					response.FailWith("User account doesn't exist, or AD refused the account.");
				}
			}

			return response;
		}



		private async Task<bool> Logout(string token) {
			ClaimsPrincipal principal = null;
			var validatedToken = loadTokenPrincipalFromRequest(out principal, token);

			if (principal != null && principal.Identity != null && !String.IsNullOrEmpty(principal.Identity.Name)) {
				log.LogInformation($"User has requested to logout: {principal.Identity.Name}");
			}
			else {
				log.LogInformation($"Unknown user has requested to logout, principal is invalid, token is invalid. SignInManager from MS Identity will attempt to proceed anyway..");
			}

			await m_signIn.SignOutAsync();
			// todo: other operations needed? Update database with datetime?

			return true;
		}
		public SecurityToken loadTokenPrincipalFromRequest(out ClaimsPrincipal principal, string token) {
			SecurityToken validatedToken = null;
			principal = null;
			try {
				//var token = context.Request.Form["token"].ToString();
				if (!String.IsNullOrEmpty(token)) {
					principal = new JwtSecurityTokenHandler().ValidateToken(token, tokenValidationParameters, out validatedToken);
				}
			}
			catch (Exception ex) {
				log.LogError("AuthServer error", ex);
				// likely: System.InvalidOperationException: Incorrect Content-Type: text/plain;charset=UTF-8
			}
			return validatedToken;
		}



		public async Task<IApplicationUser> ADRegisterUser(AuthResponseDetails response, ADUser ad_user, string withPassword = "") {
			IApplicationUser user = null;

			var newRecord = new ApplicationUser() {
				FirstName = ad_user.GivenName,
				LastName = ad_user.Surname,
				Email = ad_user.EmailAddress,
				DisplayName = (String.IsNullOrEmpty(ad_user.DisplayName)) ? ad_user.GivenName : ad_user.DisplayName,
				UserName = ad_user.SamAccountName,
				isActiveDirectory = true,
				isHidden = false,
			};
			if (!String.IsNullOrEmpty(newRecord.Email)) {
				newRecord.Email = $"{newRecord.FirstName}{newRecord.LastName.First()}@mydomain.com";
			}
			var identityResult = await m_users.CreateAsync(newRecord);

			if (identityResult.Succeeded) {
				var db_user = await m_users.FindByNameAsync(ad_user.SamAccountName);
				await m_users.SetLockoutEnabledAsync(db_user, false);
				if (!String.IsNullOrEmpty(withPassword)) {
					await m_users.AddPasswordAsync(db_user, withPassword);
				}

				if (ad_user.MatchedGroupNames.Any()) {
					var validated_groups = m_cache.Groups.Where(x => ad_user.MatchedGroupNames.Any(y => x.Name == y)).Select(x => x.Id).ToList();
					await m_groups.SetUserGroupsAsync(db_user.Id, validated_groups.ToArray());
				}

				var users = m_cache.Users.Where(x => x.Id == db_user.Id);
				user = users.First();
			}
			else {
				if (identityResult.Errors.Any()) {
					var err = identityResult.Errors.First();
					response.FailWith(err.Code + " - " + err.Description);

					log.LogError(err.Description);
				}
				else {
					response.FailWith("User account doesn't exist, or AD refused the account.");

					log.LogError("User account doesn't exist, or AD refused the account.");
				}
			}
			return user;
		}
		private async Task<AuthResponseDetails> ADRawSignIn(string username, string password) {
			var response = new AuthResponseDetails();

			ADUser ad_user = null;
			try {
				ad_user = await m_ad.MatchByPassword(username, password);
			}catch(Exception ex) {
				log.LogError(ex, "AD Auth attempt failed to operate.");
			}
			if (ad_user != null) {
				IApplicationUser user = null;
				var users = m_cache.Users.Where(x => x.UserName.ToLower() == username.ToLower());
				if (users.Any()) {
					user = users.First();
					// user already existed. Let's sync their groups.
					await ADSyncGroups(m_cache, m_groups, user, ad_user, config_identity.AD.GroupForceViewerMinimum, config_identity.AD.GroupForceViewerMinimum);

					// update user's local database password. useful if ad goes offline?
					var db_user = await m_users.FindByIdAsync(user.Id);
					await m_users.RemovePasswordAsync(db_user);
					await m_users.AddPasswordAsync(db_user, password);
				}

				if (user == null) { // we validated them in ad, so try and register them if non existent.
					user = await ADRegisterUser(response, ad_user, password);
				}

				if (user != null) {
					await m_hooks.onUserLoginAsync(context.RequestServices, user, ad_user.Principal);

					var authDetails = AuthenticatedResponse(context, m_cache, user, null, out SecurityToken token);
					response.RespondWith(authDetails);
					return response;
				}
			}
			response.FailWith("Invalid username or password.");
			return response;
		}

		// these two are static, for code-reuse. Admin area has button to trigger these two.
		public static async Task<bool> ADSyncGroups(IDBMemoryCache m_cache, IGroupManager m_groups, IApplicationUser user, ADUser ad_user, bool forceCascadeGroups = false, bool grantADusersAccessByDefault = false) {
			// get the user's current groups, excluding built-in. We need to know if they were assigned a custom group, so we can persist that through the changeset.
			var defaults = typeof(DefaultGroups).StaticFieldsOf(typeof(IApplicationGroup)).Select(x => x.Name);
			var default_groups = m_cache.Groups.Where(x => defaults.Any(y => x.Name == y));

			var current_groups = m_cache.UserGroups.Where(x => x.ApplicationUserId == user.Id);
			var custom_groups = current_groups.Where(x => !default_groups.Any(y => y.Id == x.ApplicationGroupId));

			// now get the groups based on AD matching.
			var groups = m_cache.Groups.Where(x => ad_user.MatchedGroupNames.Any(y => y.Equals(x.Name)));
			var group_ids = groups.Select(x => x.Id).ToList();

			// with that, we can apply onto the result set from AD, the custom ones in database previously. if any.
			if (custom_groups.Any()) {
				group_ids.AddRange(custom_groups.Select(x => x.ApplicationGroupId));
			}
			group_ids = group_ids.Distinct().ToList(); // safety check.

			// if system admins intend for all users authenticated by AD to have basic access, then ensure we force the viewer group onto the stack when no group is assigned.
			// basically -- IT should be managing the permissions in AD better. If they fail to do so, people can't access system. This bypasses that when they have a valid AD login.
			if (grantADusersAccessByDefault && !group_ids.Any()) {
				group_ids.Add(m_cache.Groups.First(x => x.Name == "Viewer").Id);
			}

			// run the sync op to force the users groups. todo: consider impact - as this wipes the users records from ApplicationUserGroups. Should be benign, but give it some thought..
			await m_groups.SetUserGroupsAsync(user.Id, group_ids.ToArray());

			// now that the groups are 100% proper, let's proceed with refreshing the associated roles for those groups, for this user.
			// warning/todo: Consider memory/cpu impact here, since it causes a refresh of the entire in-memory cache of UserRoles. ie potentially 40 roles per user times 100 users or more = 4000+ memory objects from database. per login.
			await m_groups.RefreshUserGroupRolesAsync(user.Id);

			return true;
		}
		public static async Task<bool> ADSyncUserInfo(ApplicationUserManager m_users, ApplicationUser db_user, ADUser ad_user) {
			db_user.FirstName = ad_user.GivenName;
			db_user.LastName = ad_user.Surname;

			if (String.IsNullOrEmpty(ad_user.EmailAddress)) {
				if (!String.IsNullOrEmpty(ad_user.UserPrincipalName) && ad_user.UserPrincipalName.Contains("@")) {
					db_user.Email = ad_user.UserPrincipalName;
				}
				else {
					db_user.Email = $"{ad_user.SamAccountName}@mydomain.com";
				}
			}
			else {
				db_user.Email = ad_user.EmailAddress;
			}

			
			db_user.DisplayName = (String.IsNullOrEmpty(ad_user.DisplayName)) ? ad_user.GivenName : ad_user.DisplayName;
			db_user.UserName = ad_user.SamAccountName;
			await m_users.UpdateAsync(db_user);
			return true;
		}


		public async Task<AuthResponseDetails> LoginWithPassword(string username, string password, bool rememberMe = false) {
			bool shouldLockoutAfterMaxAttempts = false; // todo: sysvar?
			var response = new AuthResponseDetails();
			var shouldRespondWithCookie = false; // we are using a VM approach now. not a middleware.

			log.LogInformation($"User {username} is attempting to login with a pass combo.");

			IApplicationUser user = null;
			var users = m_cache.Users.Where(x => x.UserName.ToLower() == username.ToLower());
			if (users.Any()) {
				user = users.First();
			}

			if (user != null) {
				if (config_identity.AD.UseADLoginFirst) {
					response = await ADRawSignIn(username, password);
					if (!response.Success) {
						log.LogInformation($"Attempted to sign in user[{username}] with AD BEFORE attempting database mode, but failed to authenticate. "+((config_identity.AD.FallbackToDatabaseOnFailure)? "Resorting to database mode as a backup routine." : ""));
						if (!config_identity.AD.FallbackToDatabaseOnFailure) {
							return response;
						}
					}
					else {
						log.LogInformation($"Successfully sync'd user[{username}] with AD. We will now proceed with natural database login via Microsoft Identity system which should succeed since we sync'd the user.");
					}
				}

				var result = await m_signIn.SignInAsync(username, password, rememberMe, shouldLockoutAfterMaxAttempts, shouldRespondWithCookie);
				if (result.Succeeded && user.Id > 0) {
					await m_hooks.onUserLoginAsync(context.RequestServices, user, result.principal);

					var authDetails = AuthenticatedResponse(context, m_cache, user, result, out SecurityToken token);
					response.RespondWith(authDetails);
					return response;
				}
				else {
					// user was found but the password doesn't work. Try and get them from AD instead.
					if (config_identity.AD.MatchUserNTLM) { // technically due to [settings.AD.UseADLoginFirst], this is a secondary AD request. Which is inefficient. Harmless, but needs improved in future. Leaving for now for Safety. The logistics flow in this class is quite obtuse/complex.
						response = await ADRawSignIn(username, password);
						return response;
					}
				}
			}
			else {
				// user wasn't found. see if we need to register them via AD.
				if (config_identity.AD.MatchUserNTLM) {
					response = await ADRawSignIn(username, password);
					return response;
				}
			}

			response.FailWith("Invalid username or password.");
			return response;
		}



		/// <summary>
		/// Static class helper to provide authentication mechanisms.
		/// Reference: https://stormpath.com/blog/token-authentication-asp-net-core
		/// Updated Article: https://developer.okta.com/blog/2018/03/23/token-authentication-aspnetcore-complete-guide
		/// </summary>
		public ResponseTokenDetails AuthenticatedResponse(HttpContext context, IDBMemoryCache m_cache, IApplicationUser user, SignInResult result, out SecurityToken securityToken) {
			var now = DateTimeOffset.Now;

			List<Claim> claims = new List<Claim>();
			var new_claims = new List<Claim> {
				// http://tools.ietf.org/html/rfc7519#section-4
				new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
				new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
				new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
				new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
				new Claim(ClaimsIdentity.DefaultNameClaimType, user.UserName),
			};

			if (HARDCODED_INCLUDE_MICROSOFT_CLAIMS) {
				// Specifically add the jti (random nonce), iat (issued timestamp), and sub (subject/user) claims.
				// You can add other claims here, if you want:
				//var claims = (List<Claim>)(await _userManager.GetClaimsAsync(user));
				claims = (context.User.Claims).ToList();
			}
			if (HARDCODED_INCLUDE_GROUPS_CLAIMS) {
				foreach (var ugroup in m_cache.UserGroups.Where(x => x.ApplicationUserId == user.Id)) {
					var group = m_cache.Groups.First(x => x.Id == ugroup.ApplicationGroupId);
					new_claims.Add(new Claim(JwtCustomClaimTypes.Group, group.Name));
				}
			}
			if (HARDCODED_INCLUDE_ROLES_CLAIMS) {
				foreach (var urole in m_cache.UserRoles.Where(x => x.UserId == user.Id)) {
					var role = m_cache.Roles.First(x => x.Id == urole.RoleId);
					new_claims.Add(new Claim(ClaimTypes.Role, role.Name));
				}
			}
			new_claims.Add(new Claim(ClaimTypes.Name, user.DisplayName));
			new_claims.Add(new Claim(ClaimTypes.Email, user.Email));

			
			new_claims.ForEach(claim => {
				//context.User.Identity.AddClaim(claim);
			});
			// add custom claims to the final list.
			claims.AddRange(new_claims);


			// Create the JWT and write it to a string
			var jwt = new JwtSecurityToken(
				token_options.Issuer, // issuer
				token_options.Audience, // audience
				claims, // claims
				now.DateTime, // notBefore
				now.DateTime.Add(token_options.Expiration), // expires
				token_options.SigningCredentials // signingCredentials
			);
			var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
			securityToken = jwt;

			// todo: consider StackExchange.Redis ()
			// we could hash the token down to a short sha256 or less, to reduce overall request size and bloat. And map that to the actual token in memory (disk persisted) for each auth'd user.
			// for now we simply respond which contains the bloated jwt token in base64 form, which our middleware utilzies to authenticate on-the-fly via microsoft identity..

			// Serialize and return the response
			var details = new ResponseTokenDetails() {
				token = encodedJwt,
				expiration = now.DateTime.Add(token_options.Expiration),
				expires_in = (int)token_options.Expiration.TotalSeconds
			};
			return details;
		}


		

	}
}
