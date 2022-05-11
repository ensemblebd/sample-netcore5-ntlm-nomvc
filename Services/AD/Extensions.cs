using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading.Tasks;

namespace WebApp.Services.AD {
	public static class IdentityExtensions {

		[SupportedOSPlatform("windows")]
		public static IQueryable<UserPrincipal> FilterUsers(this IQueryable<UserPrincipal> principals) =>
			principals.Where(x => x.Guid.HasValue);


		[SupportedOSPlatform("windows")]
		public static IQueryable<ADUser> SelectAdUsers(this IQueryable<UserPrincipal> principals) =>
			principals.Select(x => ADUser.From(x));

	}
}
