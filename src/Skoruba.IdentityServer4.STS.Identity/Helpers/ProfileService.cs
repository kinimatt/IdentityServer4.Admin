using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;
using Skoruba.IdentityServer4.Admin.EntityFramework.Shared.Entities.Identity;
using static IdentityServer4.IdentityServerConstants;

namespace Skoruba.IdentityServer4.STS.Identity.Helpers
{
    public class ProfileService : IProfileService
    {
        private readonly UserManager<UserIdentity> _userManager;
        private readonly IUserClaimsPrincipalFactory<UserIdentity> _claimsFactory;
        
        public ProfileService(UserManager<UserIdentity> userManager,IUserClaimsPrincipalFactory<UserIdentity> claimsFactory)
        {
            _userManager = userManager;
            _claimsFactory = claimsFactory;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var subject = context.Subject;
            if (subject == null) throw new ArgumentNullException(nameof(context.Subject));

            var subjectId = subject.GetSubjectId();

            var user = await _userManager.FindByIdAsync(subjectId);
            if (user == null)
                throw new ArgumentException("Invalid subject identifier");


            var additionalClaimTypes = new List<string>();

            foreach (var identityResource in context.RequestedResources.IdentityResources)
            {
                foreach (var userClaim in identityResource.UserClaims)
                {
                    if(!additionalClaimTypes.Contains(userClaim)){
                        additionalClaimTypes.Add(userClaim);
                    }
                }
            }

            var principal = await _claimsFactory.CreateAsync(user);
            var pclaims = principal.Claims.ToList();

            var claims = new List<Claim>();
            foreach (var item in additionalClaimTypes)
            {
                var claim = pclaims.FirstOrDefault(c=>c.Type==item);
                if(claim!=null){
                    claims.Add(claim);
                }
            }

            if(additionalClaimTypes.Contains(JwtClaimTypes.Role)){
                if (_userManager.SupportsUserRole)
                {
                    var roles = await _userManager.GetRolesAsync(user);
                    claims.AddRange(roles.Select(role => new Claim(JwtClaimTypes.Role, role)));
                }
            }

            
            //var claims = await GetClaimsFromUser(user, additionalClaimTypes);
            context.IssuedClaims.AddRange(claims);

            
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            var subject = context.Subject;
            if (subject == null) throw new ArgumentNullException(nameof(context.Subject));

            var subjectId = subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(subjectId);

            context.IsActive = false;

            if (user != null)
            {
                if (_userManager.SupportsUserSecurityStamp)
                {
                    var security_stamp = subject.Claims.Where(c => c.Type == "security_stamp").Select(c => c.Value).SingleOrDefault();
                    if (security_stamp != null)
                    {
                        var db_security_stamp = await _userManager.GetSecurityStampAsync(user);
                        if (db_security_stamp != security_stamp)
                            return;
                    }
                }

                context.IsActive =
                    !user.LockoutEnabled ||
                    !user.LockoutEnd.HasValue ||
                    user.LockoutEnd <= DateTime.Now;
            }
        }

        private async Task<IEnumerable<Claim>> GetClaimsFromUser(UserIdentity user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, user.Id),
                new Claim(JwtClaimTypes.PreferredUserName, user.UserName)
            };

            if (_userManager.SupportsUserEmail)
            {
                claims.AddRange(new[]
                {
                    new Claim(JwtClaimTypes.Email, user.Email),
                    //new Claim(JwtClaimTypes.EmailVerified, user.EmailConfirmed ? "true" : "false", System.Security.Claims.ClaimValueTypes.Boolean)
                });
            }
            /*
            if (_userManager.SupportsUserPhoneNumber && !string.IsNullOrWhiteSpace(user.PhoneNumber))
            {
                claims.AddRange(new[]
                {
                    new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber),
                    new Claim(JwtClaimTypes.PhoneNumberVerified, user.PhoneNumberConfirmed ? "true" : "false", System.Security.Claims.ClaimValueTypes.Boolean)
                });
            }

            if (_userManager.SupportsUserClaim)
            {
                claims.AddRange(await _userManager.GetClaimsAsync(user));
            }
            */
            if (_userManager.SupportsUserRole)
            {
                var roles = await _userManager.GetRolesAsync(user);
                claims.AddRange(roles.Select(role => new Claim(JwtClaimTypes.Role, role)));
            }

            return claims;
        }
    }
}