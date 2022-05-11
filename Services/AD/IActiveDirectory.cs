using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebApp.Models;
using WebApp.Services;

namespace WebApp.Services.AD {

	public interface IActiveDirectory : IDisposable {
		Task<ADUser> GetUser(IIdentity identity);
		Task<ADUser> GetUser(string samAccountName);
		Task<ADUser> GetUser(Guid guid);
		Task<ADUser> MatchByPassword(String username, string pwd);

		//public Task<List<ADUser>> GetDomainUsers();
		Task<List<ADUser>> FindDomainUser(string search);
	}

}
