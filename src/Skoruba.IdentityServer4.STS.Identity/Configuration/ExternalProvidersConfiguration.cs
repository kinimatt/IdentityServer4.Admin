﻿namespace Skoruba.IdentityServer4.STS.Identity.Configuration
{
    public class ExternalProvidersConfiguration
    {
        public bool UseGitHubProvider { get; set; }
        public string GitHubClientId { get; set; }
        public string GitHubClientSecret { get; set; }

        public bool UseFacebookProvider { get; set; }
        public string FacebookClientId { get; set; }
        public string FacebookClientSecret { get; set; }

        public bool UseGoogleProvider { get; set; }
        public string GoogleClientId { get; set; }
        public string GoogleClientSecret { get; set; }
    }
}
