using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebApp.Models;

namespace WebApp.Services.AD {
	[SupportedOSPlatform("windows")]
	public class ImplLDAPDirectoryServices : IActiveDirectory {
		ILogger log;
		IADSettings settings;
		IDBMemoryCache cache;
		List<string> valid_groups = new List<string>();
		string connectionString;

		public ImplLDAPDirectoryServices(ILoggerFactory loggerFactory, IOptionsSnapshot<IADSettings> _settings, IDBMemoryCache cache) {
			log = loggerFactory.CreateLogger<ImplLDAPDirectoryServices>();
			this.settings = _settings.Value;
			this.cache = cache;
			cache.Groups.ForEach(x => valid_groups.Add(x.AD_GroupName));
			connectionString = settings.LDAPConnectionString();
		}
		public void Dispose() {
			
		}

		private void LoaderUserGroups(ADUser user, DirectoryEntry orig_entry) {
			var memberOf = orig_entry.Properties["memberOf"];

			//using (var domainContext = (props.SecureLDAP ? new PrincipalContext(ContextType.Domain, domainName, props.AD_PATH2SECURITYGROUPS, ContextOptions.Negotiate | ContextOptions.SecureSocketLayer) : new PrincipalContext(ContextType.Domain, domainName)))
			//using (var user = UserPrincipal.FindByIdentity(domainContext, userName))
			using (var searcher = new DirectorySearcher(new DirectoryEntry(connectionString))) {
				searcher.Filter = String.Format("(&(objectCategory=group)(member={0}))", user.DistinguishedName);
				searcher.SearchScope = System.DirectoryServices.SearchScope.Subtree;
				searcher.PropertiesToLoad.Add("cn");

				foreach (SearchResult entry in searcher.FindAll()) {
					if (entry.Properties.Contains("cn")) {
						var group_name = entry.Properties["cn"][0].ToString();
						user.FoundGroupNames.Add(group_name);
					}
				}
			}

			foreach (var g in cache.Groups) {
				var matched = user.FoundGroupNames.Where(x => x.ToLower().Contains(g.AD_GroupName.ToLower()));
				if (matched.Any()) {
					if (!user.MatchedGroupNames.Contains(g.Name)) {
						user.MatchedGroupNames.Add(g.Name);
					}
				}
			}
		}


		public async Task<ADUser> GetUser(IIdentity identity) {
			return await GetUser(identity.Name);
		}
		public async Task<ADUser> GetUser(string samAccountName) {
			ADUser user = null;
			DirectoryEntry entry = null;

			using (var ds = new DirectorySearcher(new DirectoryEntry(connectionString))) {
				ds.Filter = $"samaccountname={samAccountName}";
				try {
					var searchResults = ds.FindAll();
					if (searchResults!=null && searchResults.Count > 0) {
						var searchResult = (SearchResult)searchResults.First();
						entry = searchResult.GetDirectoryEntry();
						user = ADUser.From(entry);
					}
					else {
						log.LogInformation("Failed to lookup: " + samAccountName);
					}
				}catch(Exception ex) {
					log.LogError(ex, "Failed to lookup: "+samAccountName);
				}
			}
			if (user!=null) {
				LoaderUserGroups(user, entry);
			}
			return await Task.FromResult(user);
		}
		public async Task<ADUser> GetUser(Guid guid) {
			ADUser user = null;
			DirectoryEntry entry = null;

			byte[] bytes = guid.ToByteArray();
			var sb = new StringBuilder();
			foreach (byte b in bytes) {
				sb.Append(string.Format(@"\{0}", b.ToString("X")));
			}
			var dest = sb.ToString();

			using (var ds = new DirectorySearcher(new DirectoryEntry(connectionString))) {
				ds.Filter = $"objectGUID={dest}";
				try {
					var searchResult = ds.FindOne();
					entry = searchResult.GetDirectoryEntry();
					user = ADUser.From(entry);
				}
				catch (Exception ex) {
					log.LogError(ex, "Failed to lookup: " + dest);
				}
			}

			if (user!=null) {
				LoaderUserGroups(user, entry);
			}
			return await Task.FromResult(user);

		}


		public async Task<ADUser> MatchByPassword(String username, string pwd) {
			ADUser user = null;
			DirectoryEntry entry = null;
			var expanded_username = username;
			if (!expanded_username.Contains("\\") && !String.IsNullOrEmpty(settings.LDAPLoginDomain)) {
				expanded_username = settings.LDAPLoginDomain + "\\" + username;
			}
			var connectionString_withoutUnit = settings.LDAPConnectionString(null);

			var has_valid_credentials = false;
			try {
				using (var de = new DirectoryEntry(connectionString_withoutUnit, expanded_username, pwd, AuthenticationTypes.Secure)) {
					if (de.Properties != null && de.Properties.Any()) {
						has_valid_credentials = true;
					}
				}
			}
			catch(Exception ex) {
				log.LogError(ex, "Failed to lookup: " + expanded_username);
			}
			if (has_valid_credentials) {
				using (var ds = new DirectorySearcher(new DirectoryEntry(connectionString))) {
					ds.Filter = $"samaccountname={username}";
					try {
						var searchResult = ds.FindOne();
						entry = searchResult.GetDirectoryEntry();
						user = ADUser.From(entry);
					}
					catch (Exception ex) {
						log.LogError(ex, "Failed to lookup: " + expanded_username);
					}
				}
			}

			if (user != null) {
				LoaderUserGroups(user, entry);
			}
			return await Task.FromResult(user);
		}

		public async Task<List<ADUser>> FindDomainUser(string search) {
			var results = new List<ADUser>();
			DirectoryEntry entry = null;

			using (var ds = new DirectorySearcher(new DirectoryEntry(connectionString))) {
				ds.Filter = $"(&(objectClass=user)(objectcategory=person)(name=*{search}*))";
				foreach (SearchResult searchResult in ds.FindAll()) {
					ADUser user = null;

					try {
						entry = searchResult.GetDirectoryEntry();
						user = ADUser.From(entry);
						results.Add(user);
					}
					catch (Exception ex) {
						//log.LogError(ex, "Failed to lookup: " + dest);
					}
				}
			}

			foreach(var user in results) {
				LoaderUserGroups(user, entry);
			}
			return await Task.FromResult(results);
		}
	}
}
