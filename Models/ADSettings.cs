using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebApp.Models {
	public class ADSettings : IADSettings {
		/// <summary>
		/// If true, natural logins (user/pass combo) will attempt to use AD first, before checking local. 
		/// This ensures the user is synchronized
		/// </summary>
		public bool UseADLoginFirst { get; set; }

		/// <summary>
		/// When a user signs in using "windows", should we match their windows account to AD?
		/// This should be on for live deployment. And perhaps test environment. But off for local dev enviros which won't be domain joined.
		/// </summary>
		public bool MatchUserNTLM { get; set; } = true;

		/// <summary>
		/// Use the local windows principal to talk to AD, instead of a raw ldap conneciton.
		/// Depending on deployment (iis app pool user), ldap may be required.
		/// </summary>
		public bool UseLocalPrincipalNotLDAP { get; set; } = true;
		/// <summary>
		/// Bypass normal windows libraries and use the Novell library with a direct connection over TCP
		/// </summary>
		public bool UseGenericLDAP { get; set; }

		// todo: flesh these out.

		public string OrganizationalUnit { get; set; }
		public string OUString() {
			return (!String.IsNullOrEmpty(OrganizationalUnit)) ? $"ou={OrganizationalUnit}," : "";
		}

		public List<string> DC { get; set; }
		public String DCString() {
			var output_items = new List<String>();
			foreach(var item in DC) {
				output_items.Add("dc="+item);
			}
			return String.Join(",", output_items);
		}
		public string LDAPCommonName { get; set; }


		// for ldap login directly over Novell library (linux supported)
		public string LDAPLoginDomain { get; set; }
		public string LDAPLoginUser { get; set; }
		public string LDAPLoginPassword { get; set; }
		public string LDAPServer { get; set; }
		public int LDAPPort { get; set; } = 389;
		public bool LDAPSecure { get; set; }
		public int LDAPSecurePort { get; set; } = 636;

		public bool FallbackToDatabaseOnFailure { get; set; }
		public bool GroupForceCascade { get; set; } = true;
		public bool GroupForceViewerMinimum { get; set; } = false;


		public string LDAPConnectionString(string ounit="") {
			if (ounit == "") ounit = OrganizationalUnit;

			var prefix = "LDAP";
			if (LDAPSecure) prefix = "LDAPS";

			var CommonName = (!String.IsNullOrEmpty(LDAPCommonName)) ? $"CN={LDAPCommonName}," : "";
			var OrgUnit = (!String.IsNullOrEmpty(ounit)) ? $"OU={ounit}," : "";
			var URL = (!String.IsNullOrEmpty(LDAPServer))? $"{LDAPServer}:{(LDAPSecure ? LDAPSecurePort : LDAPPort)}/" : "";
			return $"{prefix}://{URL}{CommonName}{OrgUnit}{DCString()}";
		}
	}
}
