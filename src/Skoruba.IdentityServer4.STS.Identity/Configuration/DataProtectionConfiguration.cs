using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Skoruba.IdentityServer4.STS.Identity.Configuration
{
    public class DataProtectionConfiguration
    {
        public string ApplicationName { get; set; }
        public bool UseLocalStorage { get; set; }
        public string LocalStoragePath { get; set; }
        public bool UseAzureBlobStorage { get; set; }
        public string AzureBlobUriWithSasToken { get; set; }
        public bool UseAzureKeyVault { get; set; }
        public string AzureKeyIdentifier { get; set; }
        public string AzureClientId { get; set; }
        public string AzureClientSecret { get; set; }
        public bool UseCertificateThumbprint { get; set; }
        public string CertificateThumbprint { get; set; }
        public bool UseCertificatePfxFile { get; set; }
        public string CertificatePfxFilePath { get; set; }
        public string CertificatePfxFilePassword { get; set; }
    }

}
