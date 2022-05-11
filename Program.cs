using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.Principal;
using WebApp.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NLog.Web;

namespace WebApp {

	public class Program {

		public static void Main(string[] args) {
			var log_factory = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config");
			var logger = log_factory.GetCurrentClassLogger();

			logger.Debug("Building host app.");
			var host = BuildWebHost(args);

			try {
				logger.Debug("Running host app.");
				host.Run();
			}
			catch (Exception ex) {
				logger.Error(ex, "Main executable failed with hard exception.");
			}
			finally {
				NLog.LogManager.Shutdown();
			}
		}

		public static IWebHost BuildWebHost(string[] args) {
			string mode = (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development").ToUpper();
			string useiis = Environment.GetEnvironmentVariable("ASPNETCORE_USE_IIS_INTEGRATION") ?? "0";
			bool IsProduction = (mode == "PRODUCTION" || mode == "PROD");
			bool UseIISIntegration = (useiis == "1");

#if (RELEASE) // force production mode when compiled in release mode. todo: Consider removing this, and giving the web.config full control.
IsProduction = true;
#endif

			// force iis integration when in production mode. 
			if ((useiis == null || useiis != "0") && IsProduction) {
				UseIISIntegration = true;
			}

			var builder = WebHost.CreateDefaultBuilder(args);
			if (!UseIISIntegration) {
				builder = builder.UseKestrel();
			}
			else {
				builder = builder.UseIISIntegration();
			}

			return builder
				.ConfigureAppConfiguration((hostingContext, builder) => {
					var env = hostingContext.HostingEnvironment; // Get the environment from our hostContext.
					
					// mandate a custom config..
					builder
						.AddJsonFile("Properties\\settings.json", optional: false, reloadOnChange: true) // primary settings file. To be used as a template for derivatives below..
						.AddJsonFile($"Properties\\settings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true) // env name will be either Production or Development. Automatic settings file loader.
						.AddJsonFile($"Properties\\settings.secrets.json", optional: true, reloadOnChange: true) // secrets shall override anything else, and is intentional EXCLUDED from git, to protect secret passwords / api keys.
						.AddEnvironmentVariables(prefix: "ASPNETCORE_");
				})
				.UseStartup<Startup>()
				.ConfigureLogging((hostingContext, logging) => {
					logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
					logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace); 
					
					logging.ClearProviders();
					logging.AddDebug();
					logging.AddConsole();
				})
				.UseNLog()
				.Build();
		}

	}
}
