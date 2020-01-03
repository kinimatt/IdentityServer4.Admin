using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Skoruba.IdentityServer4.STS.Identity.ViewModels.Account
{
    public class RegisterResponseViewModel
    {
        public string Email { get; set; }
        public string UserId { get; set; }
        public string VendorId { get; set; }

    }
}
