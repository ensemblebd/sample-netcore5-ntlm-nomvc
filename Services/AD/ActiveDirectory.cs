using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebApp.Models;
using WebApp.Services.AD;

namespace WebApp.Services {
	public class ActiveDirectory : IActiveDirectory {
		ILogger log;
		IADSettings settings;
		IServiceProvider provider;
		IActiveDirectory impl;

		public ActiveDirectory(ILoggerFactory loggerFactory, IServiceProvider provider, IOptionsSnapshot<IADSettings> _settings) {
			log = loggerFactory.CreateLogger<ActiveDirectory>();
			this.settings = _settings.Value;
			this.provider = provider;

			bool isWindows = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

			if (isWindows && !settings.UseGenericLDAP) {
				if (settings.UseLocalPrincipalNotLDAP) {
					impl = (IActiveDirectory)ActivatorUtilities.CreateInstance(provider, typeof(AD.ImplLocalPrincipal));
				}
				else {
					impl = (IActiveDirectory)ActivatorUtilities.CreateInstance(provider, typeof(AD.ImplLDAPDirectoryServices));
				}
			}
			else {
				impl = (IActiveDirectory)ActivatorUtilities.CreateInstance(provider, typeof(AD.ImplLDAPNovell));
			}
		}
		public void Dispose() {
			
		}


		public async Task<ADUser> GetUser(IIdentity identity) {
			return await impl.GetUser(identity);
		}
		public async Task<ADUser> GetUser(string samAccountName) {
			return await impl.GetUser(samAccountName);
		}
		public async Task<ADUser> GetUser(Guid guid) {
			return await impl.GetUser(guid);
		}
		public async Task<ADUser> MatchByPassword(String username, string pwd) {
			return await impl.MatchByPassword(username, pwd);
		}
		//public Task<List<ADUser>> GetDomainUsers();
		public async Task<List<ADUser>> FindDomainUser(string search) {
			return await impl.FindDomainUser(search);
		}
	}


}
