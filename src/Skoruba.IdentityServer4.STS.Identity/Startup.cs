using HealthChecks.UI.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.DbContexts;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Identity;
using Skoruba.IdentityServer4.STS.Identity.Configuration;
using Skoruba.IdentityServer4.STS.Identity.Configuration.Constants;
using Skoruba.IdentityServer4.STS.Identity.Configuration.Interfaces;
using Skoruba.IdentityServer4.STS.Identity.Helpers;
using System;
using IdentityModel.Client;
using System.Net.Http;
using Microsoft.AspNetCore.DataProtection;
using System.IO;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IdentityServer4.Services;
using Microsoft.OpenApi.Models;
using System.Collections.Generic;

namespace Skoruba.IdentityServer4.STS.Identity
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Environment { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Configuration = configuration;
            Environment = environment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var rootConfiguration = CreateRootConfiguration();
            services.AddSingleton(rootConfiguration);

            // Register DbContexts for IdentityServer and Identity
            RegisterDbContexts(services);

            // Add email senders which is currently setup for SendGrid and SMTP
            services.AddEmailSenders(Configuration);

            // Add services for authentication, including Identity model and external providers
            RegisterAuthentication(services);
            
            // Add all dependencies for Asp.Net Core Identity in MVC - these dependencies are injected into generic Controllers
            // Including settings for MVC and Localization
            // If you want to change primary keys or use another db model for Asp.Net Core Identity:
            services.AddMvcWithLocalization<UserIdentity, string>(Configuration).AddNewtonsoftJson();

            // Add authorization policies for MVC
            RegisterAuthorization(services);


            services.AddIdSHealthChecks<IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext, AdminIdentityDbContext>(Configuration);

            RegisterDataProtection(services);

            services.AddHttpClient("IDS", c =>
            {
                c.BaseAddress = new Uri(Configuration.GetValue<string>("BaseUrl"));
            });

            services.AddSingleton<IDiscoveryCache>(r =>
            {
                var factory = r.GetRequiredService<IHttpClientFactory>();
                return new DiscoveryCache(Configuration.GetValue<string>("BaseUrl"), () => factory.CreateClient());
            });
            
            services.AddTransient<IProfileService, ProfileService>();

            // Register the Swagger generator, defining 1 or more Swagger documents
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });
                 c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = @"JWT Authorization header using the Bearer scheme. \r\n\r\n 
                                Enter 'Bearer' [space] and then your token in the text input below.
                                \r\n\r\nExample: 'Bearer 12345abcdef'",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement()
                {
                    {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        },
                        Scheme = "oauth2",
                        Name = "Bearer",
                        In = ParameterLocation.Header,

                        },
                        new List<string>()
                    }
                    });
            });
            
            //CORS 
            services.AddCors(options =>
            {
                options.AddPolicy("all",
                builder =>
                {
                        builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                    /*builder.WithOrigins("http://localhost",
                                        "https://localhost");
                    */
                });
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // Add custom security headers
            app.UseSecurityHeaders();
            
            app.UseCors("all");

            app.UseStaticFiles();
            UseAuthentication(app);
            app.UseMvcLocalizationServices();

            app.UseRouting();
            app.UseAuthorization();

            app.UseEndpoints(endpoint => 
            { 
                endpoint.MapDefaultControllerRoute();
                endpoint.MapHealthChecks("/health", new HealthCheckOptions
                {
                    ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
                });
            });
        }

        public virtual void RegisterDataProtection(IServiceCollection services)
        {
       

        var dataProtectionConfiguration = Configuration.GetSection(nameof(DataProtectionConfiguration)).Get<DataProtectionConfiguration>();


            var builder = services.AddDataProtection()
             .SetDefaultKeyLifetime(TimeSpan.FromDays(365));

            if (!string.IsNullOrWhiteSpace(dataProtectionConfiguration.ApplicationName))
            {
                builder.SetApplicationName(dataProtectionConfiguration.ApplicationName);
            }
            

            if (dataProtectionConfiguration.UseLocalStorage)
            {
                if (string.IsNullOrWhiteSpace(dataProtectionConfiguration.LocalStoragePath))
                {
                    throw new Exception("Data protection configuration: Local Storage path not specified");
                }

                if (Directory.Exists(dataProtectionConfiguration.LocalStoragePath))
                {
                    try
                    {
                        builder.PersistKeysToFileSystem(new DirectoryInfo(dataProtectionConfiguration.LocalStoragePath));
                    }
                    catch (Exception e)
                    {
                        throw new Exception("There was an error adding the key file - during the creation of the signing key", e);
                    }
                }
                else
                {
                    throw new Exception($"Data protection configuration: {dataProtectionConfiguration.LocalStoragePath} not found");
                }
            } 

            if (dataProtectionConfiguration.UseAzureBlobStorage)
            {
                if (string.IsNullOrWhiteSpace(dataProtectionConfiguration.AzureBlobUriWithSasToken))
                {
                    throw new Exception("Data protection configuration: AzureBlobUriWithSasToken not specified");
                }

                try
                    {
                        builder.PersistKeysToAzureBlobStorage(new Uri(dataProtectionConfiguration.AzureBlobUriWithSasToken));
                     }
                    catch (Exception e)
                    {
                        throw new Exception("Data protection configuration: There was an error adding azure blog storage", e);
                    }
            }
            
            if (dataProtectionConfiguration.UseAzureKeyVault)
            {
                if (string.IsNullOrWhiteSpace(dataProtectionConfiguration.AzureKeyIdentifier))
                {
                    throw new Exception("Data protection configuration: AzureKeyIdentifier not specified");
                }

                try
                    {
                        builder.ProtectKeysWithAzureKeyVault(dataProtectionConfiguration.AzureKeyIdentifier, dataProtectionConfiguration.AzureClientId, dataProtectionConfiguration.AzureClientSecret);
                     }
                    catch (Exception e)
                    {
                        throw new Exception("Data protection configuration: There was an error adding azure key vault", e);
                    }
            }

            if (dataProtectionConfiguration.UseCertificateThumbprint)
            {
                if (string.IsNullOrWhiteSpace(dataProtectionConfiguration.CertificateThumbprint))
                {
                    throw new Exception("Data protection configuration: CertificateThumbprint not specified");
                }

                try
                    {
                        builder.ProtectKeysWithCertificate(dataProtectionConfiguration.CertificateThumbprint);
                    }
                    catch (Exception e)
                    {
                        throw new Exception("Data protection configuration: There was an error adding CertificateThumbprint", e);
                    }
            }

            if (dataProtectionConfiguration.UseCertificatePfxFile)
            {
                if (string.IsNullOrWhiteSpace(dataProtectionConfiguration.CertificatePfxFilePath))
                {
                    throw new Exception("Data protection configuration: CertificatePfxFilePath not specified");
                }


                if (File.Exists(dataProtectionConfiguration.CertificatePfxFilePath))
                {
                    try
                    {
                        builder.ProtectKeysWithCertificate(new X509Certificate2(dataProtectionConfiguration.CertificatePfxFilePath, dataProtectionConfiguration.CertificatePfxFilePassword));
                    }
                    catch (Exception e)
                    {
                        throw new Exception("Data protection configuration: There was an error adding the CertificatePfxFilePath", e);
                    }
                }
                else
                {
                    throw new Exception($"Data protection configuration: {dataProtectionConfiguration.CertificatePfxFilePath} not found");
                }
                
            }
            
            //TODO use this when exipred keys needs to be used
            /*.UnprotectKeysWithAnyCertificate(new X509Certificate2("certificate_old_1.pfx", "password_1"),
                new X509Certificate2("certificate_old_2.pfx", "password_2"));*/

        }

        public virtual void RegisterDbContexts(IServiceCollection services)
        {
            services.RegisterDbContexts<AdminIdentityDbContext, IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext>(Configuration);
        }

        public virtual void RegisterAuthentication(IServiceCollection services)
        {
            services.AddAuthenticationServices<AdminIdentityDbContext, UserIdentity, UserIdentityRole>(Configuration);
            services.AddIdentityServer<IdentityServerConfigurationDbContext, IdentityServerPersistedGrantDbContext, UserIdentity>(Configuration);
        }

        public virtual void RegisterAuthorization(IServiceCollection services)
        {
            var rootConfiguration = CreateRootConfiguration();
            services.AddAuthorizationPolicies(rootConfiguration);
        }

        public virtual void UseAuthentication(IApplicationBuilder app)
        {
            app.UseIdentityServer();
        }

        protected IRootConfiguration CreateRootConfiguration()
        {
            var rootConfiguration = new RootConfiguration();
            Configuration.GetSection(ConfigurationConsts.AdminConfigurationKey).Bind(rootConfiguration.AdminConfiguration);
            Configuration.GetSection(ConfigurationConsts.RegisterConfigurationKey).Bind(rootConfiguration.RegisterConfiguration);
            return rootConfiguration;
        }
    }
}
