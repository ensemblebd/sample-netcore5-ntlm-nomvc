using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;
using WebApp.Models;

namespace WebApp.Services.AD {
	public class ADUser {
		private static List<PropertyInfo> ownProperties;
		private static void loadOwnPropertiesIfNeeded() {
			if (ownProperties != null) return;
			ownProperties = new List<PropertyInfo>();
			foreach (var prop in typeof(ADUser).GetProperties()) {
				ownProperties.Add(prop);
			}
		}

		public ADUser() {

		}

		public DateTime? AccountExpirationDate { get; set; }
		public DateTime? AccountLockoutTime { get; set; }
		public int BadLogonCount { get; set; }
		public string Description { get; set; }
		public string DisplayName { get; set; }
		public string DistinguishedName { get; set; }
		public string Domain { get; set; }
		[ADFieldMap("mail")]
		public string EmailAddress { get; set; }
		public string EmployeeId { get; set; }
		public bool? Enabled { get; set; }
		public string GivenName { get; set; }
		[ADFieldMap("objectGUID")]
		public Guid? Guid { get; set; }
		public string HomeDirectory { get; set; }
		public string HomeDrive { get; set; }
		public DateTime? LastBadPasswordAttempt { get; set; }
		public DateTime? LastLogon { get; set; }
		public DateTime? LastPasswordSet { get; set; }
		public string MiddleName { get; set; }
		public string Name { get; set; }
		public bool PasswordNeverExpires { get; set; }
		public bool PasswordNotRequired { get; set; }
		public string SamAccountName { get; set; }

		public string ScriptPath { get; set; }
		[ADFieldMap("objectSID")]
		public SecurityIdentifier Sid { get; set; }
		[ADFieldMap("sn")]
		public string Surname { get; set; }
		public bool UserCannotChangePassword { get; set; }
		public string UserPrincipalName { get; set; }
		public string VoiceTelephoneNumber { get; set; }

		public List<string> FoundGroupNames { get; set; } = new List<string>();
		public List<string> MatchedGroupNames { get; set; } = new List<string>();


		internal System.Security.Claims.ClaimsPrincipal Principal { get; set; }

		internal static ADUser From(LdapEntry entry) {
			loadOwnPropertiesIfNeeded();

			var user = new ADUser() {
				Guid = new Guid((byte[])(Array)entry.GetAttribute("objectGuid").ByteValue),
				//Sid = new SecurityIdentifier(entry.GetAttribute("objectSid").StringValue) // not available on linux
			};
			var materializedProperties = new Dictionary<string, object>();
			foreach (var attrib in entry.GetAttributeSet()) {
				materializedProperties.Add(attrib.Name, attrib.StringValue);
			}
			foreach (var kvp in materializedProperties) {
				var props = ownProperties.Where(x =>
					x.Name.ToLower().Equals(kvp.Key.ToLower())
					|| x.GetCustomAttributes(false).Any(y =>
						y.GetType() == typeof(ADFieldMapAttribute)
						&& ((ADFieldMapAttribute)y).acceptedNames.Any(z => z.ToLower().Equals(x.Name.ToLower()))
					)
				);
				if (props.Any()) {
					var prop = props.First();
					object value = null;
					var svalue = (string)kvp.Value;

					if (prop.PropertyType == typeof(bool)) {
						var temp = 0;
						if (Int32.TryParse(svalue, out temp)) {
							value = temp;
						}
						else if (svalue.ToLower() == "true") {
							value = true;
						}
						else value = false;
					}
					else if (prop.PropertyType == typeof(int)) {
						var temp = 0;
						if (Int32.TryParse(svalue, out temp)) {
							value = temp;
						}
					}
					else if (prop.PropertyType == typeof(string)) {
						value = svalue;
					}
					else if (prop.PropertyType == typeof(DateTime?)) {
						DateTime temp = DateTime.MinValue;
						var raw = svalue;
						if (DateTime.TryParse(raw, out temp)) {
							value = temp;
						}
					}

					if (value != null) {
						prop.SetValue(user, value);
					}
				}
			}
			user.Principal = new ClaimsPrincipal(new ClaimsIdentity(new System.Security.Claims.Claim[] {
				new Claim(ClaimTypes.NameIdentifier, user.SamAccountName),
				new Claim(ClaimsIdentity.DefaultNameClaimType, user.SamAccountName),
			}, "ntlm"));

			return user;
		}

		[SupportedOSPlatform("windows")]
		internal static ADUser From(DirectoryEntry entry) {
			loadOwnPropertiesIfNeeded();

			var user = new ADUser() {
				Guid = new Guid((byte[])(Array)entry.Properties["objectGuid"].Value),
				Sid = new SecurityIdentifier((byte[])entry.Properties["objectSid"][0], 0)
			};
			var materializedProperties = new Dictionary<string, System.DirectoryServices.PropertyValueCollection>();
			foreach (string de_property_name in entry.Properties.PropertyNames) {
				materializedProperties.Add(de_property_name, entry.Properties[de_property_name]);
			}
			foreach (var kvp in materializedProperties) {
				var prop = locateOwnProp(kvp.Key);
				if (prop != null) {
					object value = null;

					var svalue = kvp.Value.Value.ToString();
					if (prop.PropertyType == typeof(bool)) {
						var temp = 0;
						if (Int32.TryParse(svalue, out temp)) {
							value = temp;
						}
						else if (svalue.ToLower() == "true") {
							value = true;
						}
						else value = false;
					}
					else if (prop.PropertyType == typeof(int)) {
						var temp = 0;
						if (Int32.TryParse(svalue, out temp)) {
							value = temp;
						}
					}
					else if (prop.PropertyType == typeof(string)) {
						if (kvp.Value.Value.GetType() == typeof(byte[])) {
							try {
								if (kvp.Key.ToLower().Contains("sid")) {
									var sid = new SecurityIdentifier((byte[])kvp.Value.Value, 0);
									value = sid.ToString();
								}
								else if (kvp.Key.ToLower().Contains("guid")) {
									value = ((byte[])kvp.Value.Value).ToString();
								}
							}
							catch(Exception ex) { }
						}
						else {
							value = svalue;
						}
					}
					else if (prop.PropertyType == typeof(DateTime?)) {
						DateTime temp = DateTime.MinValue;
						if (kvp.Value.Value.GetType() == typeof(long)) {
							var lvalue = (long)kvp.Value.Value;
							temp = DateTime.FromFileTime(lvalue);
						}
						else {
							if (DateTime.TryParse(svalue, out temp)) {
								value = temp;
							}
						}
					}

					if (value != null) {
						prop.SetValue(user, value);
					}
				}
			}
			user.Principal = new ClaimsPrincipal(new ClaimsIdentity(new System.Security.Claims.Claim[] {
				new Claim(ClaimTypes.NameIdentifier, user.SamAccountName),
				new Claim(ClaimsIdentity.DefaultNameClaimType, user.SamAccountName),
			},"ntlm"));
			return user;
		}

		[SupportedOSPlatform("windows")]
		public static ADUser From(UserPrincipal principal) {
			loadOwnPropertiesIfNeeded();
			var user = new ADUser();

			var targetProps = typeof(UserPrincipal).GetProperties();
			foreach(var tprop in targetProps) {
				var prop = locateOwnProp(tprop.Name);
				if (prop != null) {
					try {
						prop.SetValue(user, tprop.GetValue(principal));
					} catch (Exception ex) { }
				}
			}
			user.Principal = new ClaimsPrincipal(new ClaimsIdentity(new System.Security.Claims.Claim[] {
				new Claim(ClaimTypes.NameIdentifier, user.SamAccountName),
				new Claim(ClaimsIdentity.DefaultNameClaimType, user.SamAccountName),
			}, "ntlm"));

			return user;
		}

		public string GetDomainPrefix() => DistinguishedName
			.Split(',')
			.FirstOrDefault(x => x.ToLower().Contains("dc"))
			.Split('=')
			.LastOrDefault()
			.ToUpper();
		

		private static PropertyInfo locateOwnProp(string name) {
			foreach(var prop in ownProperties) {
				if (prop.Name.ToLower() == name.ToLower()) return prop;
				var attr = prop.GetCustomAttribute<ADFieldMapAttribute>();
				if (attr!=null) {
					if (attr.acceptedNames.Any(x=> x.ToLower().Equals(name.ToLower()))) {
						return prop;
					}
				}
			}
			return null;
		}
	}

	[AttributeUsage(AttributeTargets.Property)]
	public class ADFieldMapAttribute : System.Attribute {
		public List<string> acceptedNames { get; set; } = new List<string>();
		public ADFieldMapAttribute(string name) {
			acceptedNames.Add(name);
		}
		public ADFieldMapAttribute(string[] names) {
			acceptedNames.AddRange(names);
		}
	}
}
