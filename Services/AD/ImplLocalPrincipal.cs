using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebApp.Models;

namespace WebApp.Services.AD {
	// ref: https://gist.github.com/JaimeStill/539af65518091f7b8e6b9e003a493baa
	[SupportedOSPlatform("windows")]
	public class ImplLocalPrincipal : IActiveDirectory {
		ILogger log;
		IADSettings settings;
		IDBMemoryCache cache;
		List<string> valid_groups = new List<string>();

		public ImplLocalPrincipal(ILoggerFactory loggerFactory, IOptionsSnapshot<IADSettings> _settings, IDBMemoryCache cache) {
			log = loggerFactory.CreateLogger<ImplLocalPrincipal>();
			this.settings = _settings.Value;
			this.cache = cache;
			cache.Groups.ForEach(x => valid_groups.Add(x.AD_GroupName));
		}
		public void Dispose() {
			
		}

		private void LoadUserGroups(ref ADUser user, UserPrincipal p) {
			user.FoundGroupNames = GetGroups(p);
			foreach(var g in cache.Groups) {
				var matched = user.FoundGroupNames.Where(x => x.ToLower().Contains(g.AD_GroupName.ToLower())); // match on AD_GroupName alone, and below we use the name for internal lookup later on to assign user groups.
				if (matched.Any()) {
					if (!user.MatchedGroupNames.Contains(g.Name)) {
						user.MatchedGroupNames.Add(g.Name);
					}
				}
			}
		}
		private List<String> GetGroups(Principal source, int depth = 0, List<String> resultset = null) {
			if (resultset == null) resultset = new List<String>();
			depth++;
			foreach (GroupPrincipal group in source.GetGroups()) {
				if (!resultset.Contains(group.Name)) {
					resultset.Add(group.Name);
					resultset = GetGroups(group, depth, resultset);
				}
			}
			return resultset;
		}


		public async Task<ADUser> GetUser(IIdentity identity) {
			ADUser ad_user = null;

			try {
				PrincipalContext context = new PrincipalContext(ContextType.Domain, settings.LDAPServer);
				UserPrincipal principal = new UserPrincipal(context);
				if (context != null) {
					principal = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, identity.Name);
				}
				ad_user = ADUser.From(principal);
				LoadUserGroups(ref ad_user, principal);
			}
			catch (Exception ex) {
				throw new Exception("Error retrieving AD User", ex);
			}

			return await Task.FromResult(ad_user);
		}
		public async Task<ADUser> GetUser(string samAccountName) {
			ADUser ad_user = null;

			try {
				PrincipalContext context = new PrincipalContext(ContextType.Domain, settings.LDAPServer);
				UserPrincipal principal = new UserPrincipal(context);
				if (context != null) {
					principal = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, samAccountName);
				}
				ad_user = ADUser.From(principal);
				LoadUserGroups(ref ad_user, principal);
			}
			catch (Exception ex) {
				throw new Exception("Error retrieving AD User", ex);
			}

			return await Task.FromResult(ad_user);
		}
		public async Task<ADUser> GetUser(Guid guid) {
			ADUser ad_user = null;

			try {
				PrincipalContext context = new PrincipalContext(ContextType.Domain, settings.LDAPServer);
				UserPrincipal principal = new UserPrincipal(context);
				if (context != null) {
					principal = UserPrincipal.FindByIdentity(context, IdentityType.Guid, guid.ToString());
				}
				ad_user = ADUser.From(principal);
				LoadUserGroups(ref ad_user, principal);
			}
			catch (Exception ex) {
				throw new Exception("Error retrieving AD User", ex);
			}

			return await Task.FromResult(ad_user);
		}

		public async Task<ADUser> MatchByPassword(string username, string pwd) {
			ADUser ad_user = null;
			try {
				PrincipalContext context = new PrincipalContext(ContextType.Domain, settings.LDAPServer);
				UserPrincipal principal = new UserPrincipal(context);
				if (context != null) {
					principal = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, username);
				}
				if (context.ValidateCredentials(username, pwd)) {
					ad_user = ADUser.From(principal);
					LoadUserGroups(ref ad_user, principal);
				}
				else {
					log.LogInformation("user auth[" + username + "] credentials invalid");
				}
			}
			catch (Exception ex) {
				log.LogError(ex.Message, ex);
				//throw new Exception("Error retrieving AD User", ex);
			}
			
			return await Task.FromResult(ad_user);
		}

		public async Task<List<ADUser>> GetDomainUsers() {
			var context = new PrincipalContext(ContextType.Domain, settings.LDAPServer);
			UserPrincipal principal = new UserPrincipal(context);
			principal.UserPrincipalName = "*@*";
			principal.Enabled = true;
			PrincipalSearcher searcher = new PrincipalSearcher(principal);
			var users = searcher.FindAll().Take(50).AsQueryable().Cast<UserPrincipal>().FilterUsers().SelectAdUsers().OrderBy(x => x.Surname).ToList();
			
			return await Task.FromResult(users);
		}
		public async Task<List<ADUser>> FindDomainUser(string search) {
			PrincipalContext context = new PrincipalContext(ContextType.Domain, settings.LDAPServer);
			UserPrincipal principal = new UserPrincipal(context);
			principal.SamAccountName = $"*{search}*";
			principal.Enabled = true;
			PrincipalSearcher searcher = new PrincipalSearcher(principal);
			var users = searcher.FindAll().AsQueryable().Cast<UserPrincipal>().FilterUsers().SelectAdUsers().OrderBy(x => x.Surname).ToList();
			/* todo: rewrite asQueryable above to perform this as well.
			foreach(var user in users) {
				LoadUserGroups(ref user, principal);
				return user;
			}*/

			return await Task.FromResult(users);
		}
	}
	
}
