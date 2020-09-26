using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Skoruba.IdentityServer4.STS.Identity.ViewModels.Account
{
    public class RegisterWithPhoneNoViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Compare("Password")]
        public string ConfirmPassword { get; set; }
        //[Required]
        public string PhoneNo { get; set; }

        //[Required]
        public string Otp { get; set; }
        public string TransactionCode { get; set; }
        public string SSOCode { get; set; }
        public string SSOType { get; set; }
        public string SSOAccessToken { get; set; }
      
    }
}
