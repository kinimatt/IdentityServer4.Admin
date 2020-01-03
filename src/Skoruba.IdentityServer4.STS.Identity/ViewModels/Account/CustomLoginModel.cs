using System.ComponentModel.DataAnnotations;

namespace Skoruba.IdentityServer4.STS.Identity.ViewModels.Account
{
    public class CustomLoginModel
    {
        [Required]
        [EmailAddress]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
    }
}