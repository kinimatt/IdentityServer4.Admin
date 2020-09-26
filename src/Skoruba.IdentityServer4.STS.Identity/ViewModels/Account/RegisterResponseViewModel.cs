using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Skoruba.IdentityServer4.STS.Identity.ViewModels.Account
{
    public class RegisterResponseViewModel
    {
        public int id { get; set; }
     
        public string email { get; set; }
        public string userId { get; set; }
        public string vendorId { get; set; }
        public string accessToken { get; set; }
        public string expiresIn { get; set; }
        public string refreshToken { get; set; }

    }
}
