using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;
using WebApp.Models;

namespace WebApp.Services.AD {
	public class ImplLDAPNovell : IActiveDirectory {
		ILogger log;
		IADSettings settings;
		IDBMemoryCache cache;
		List<string> valid_groups = new List<string>();

		public ImplLDAPNovell(ILoggerFactory loggerFactory, IOptionsSnapshot<IADSettings> _settings, IDBMemoryCache cache) {
			log = loggerFactory.CreateLogger<ImplLDAPNovell>();
			this.settings = _settings.Value;
			this.cache = cache;
			cache.Groups.ForEach(x => valid_groups.Add(x.AD_GroupName));
		}

		private void LoaderUserGroups(LdapConnection conn, ref ADUser user, LdapEntry entry) {
			var enum_g = entry.GetAttribute("memberOf").StringValues;
			while (enum_g.MoveNext()) {
				user.FoundGroupNames.Add(enum_g.Current);
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
		public void Dispose() {
			
		}

		public async Task<ADUser> GetUser(IIdentity identity) {
			return await GetUser(identity.Name);
		}
		public async Task<ADUser> GetUser(string samAccountName) {
			ADUser user = null;

			var conn = new LdapConnection();
			conn.Connect(settings.LDAPServer, settings.LDAPPort);
			conn.Bind($"{settings.LDAPLoginDomain}\\{settings.LDAPLoginUser}", settings.LDAPLoginPassword);
			log.LogDebug(conn.GetSchemaDn());

			var filter = "samaccountname=" + samAccountName;
			var desiredAttributes = new List<string>() {
				// blank to return all.
			};
			var typesOnly = false; // if true - will return only the property names not the values.

			var lsc = conn.Search($"{settings.OUString()}{settings.DCString()}", LdapConnection.ScopeSub, filter, desiredAttributes.ToArray(), typesOnly);
			while (lsc.HasMore()) {
				LdapEntry nextEntry = null;
				try {
					nextEntry = lsc.Next();
				}
				catch (LdapException e) {
					log.LogError("Error: " + e.LdapErrorMessage, e); // temporary, remove me soon.
					//Exception is thrown, go for next entry
					continue;
				}

				var DisplayName = nextEntry.GetAttribute("displayName").StringValue;
				var UserADId = new Guid((byte[])(Array)nextEntry.GetAttribute("objectGuid").ByteValue).ToString();
				var EMail = nextEntry.GetAttribute("mail").StringValue;
				log.LogDebug(DisplayName);
				log.LogDebug(UserADId);
				log.LogDebug(EMail);
					
				user = ADUser.From(nextEntry);
				LoaderUserGroups(conn, ref user, nextEntry);
				break; // break on first valid found item.
			}

			conn.Disconnect();

			return await Task.FromResult(user);
		}
		public async Task<ADUser> GetUser(Guid guid) {
			ADUser user = null;

			var conn = new LdapConnection();
			conn.Connect(settings.LDAPServer, settings.LDAPPort);
			conn.Bind($"{settings.LDAPLoginDomain}\\{settings.LDAPLoginUser}", settings.LDAPLoginPassword);
			log.LogDebug(conn.GetSchemaDn());

			byte[] bytes = guid.ToByteArray();
			var sb = new StringBuilder();
			foreach (byte b in bytes) {
				sb.Append(string.Format(@"\{0}", b.ToString("X")));
			}
			var filter = "guid="+sb.ToString();
			var desiredAttributes = new List<string>() {
				// blank to return all.
			};
			var typesOnly = false; // if true - will return only the property names not the values.

			var lsc = conn.Search($"{settings.OUString()}{settings.DCString()}", LdapConnection.ScopeSub, filter, desiredAttributes.ToArray(), typesOnly);
			while (lsc.HasMore()) {
				LdapEntry nextEntry = null;
				try {
					nextEntry = lsc.Next();
				}
				catch (LdapException e) {
					log.LogError("Error: " + e.LdapErrorMessage, e); // temporary, remove me soon.
					//Exception is thrown, go for next entry
					continue;
				}

				user = ADUser.From(nextEntry);
				break; // break on first valid found item.
			}

			conn.Disconnect();

			return await Task.FromResult(user);
		}


		public async Task<ADUser> MatchByPassword(String username, string pwd) {
			ADUser user = null;
			// todo: needs researched and coded.
			return await Task.FromResult(user);
		}

		public async Task<List<ADUser>> FindDomainUser(string search) {
			var results = new List<ADUser>();

			var conn = new LdapConnection();
			conn.Connect(settings.LDAPServer, settings.LDAPPort);
			conn.Bind($"{settings.LDAPLoginDomain}\\{settings.LDAPLoginUser}", settings.LDAPLoginPassword);
			log.LogDebug(conn.GetSchemaDn());

			var filter = "*";
			var desiredAttributes = new List<string>() {
				// blank to return all.
			};
			var typesOnly = false; // if true - will return only the property names not the values.

			var lsc = conn.Search($"{settings.OUString()}{settings.DCString()}", LdapConnection.ScopeSub, filter, desiredAttributes.ToArray(), typesOnly);
			while (lsc.HasMore()) {
				ADUser user = null;
				LdapEntry nextEntry = null;
				try {
					nextEntry = lsc.Next();
				}
				catch (LdapException e) {
					log.LogError("Error: " + e.LdapErrorMessage, e); // temporary, remove me soon.
					//Exception is thrown, go for next entry
					continue;
				}
				user = ADUser.From(nextEntry);
				results.Add(user);
			}

			conn.Disconnect();

			return await Task.FromResult(results);
		}
	}
}
