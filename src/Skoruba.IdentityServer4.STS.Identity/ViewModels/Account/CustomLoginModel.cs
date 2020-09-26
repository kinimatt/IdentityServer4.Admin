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
    public class CustomLoginPhoneNoModel
    {
       
       [Required]
        public string TransactionCode { get; set; }
        [Required]
        public string PhoneNo { get; set; }
        [Required]
        public string Otp { get; set; }
    }
}