// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

// Original file: https://github.com/IdentityServer/IdentityServer4.Samples
// Modified by Jan Škoruba

using System;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Skoruba.IdentityServer4.STS.Identity.Configuration;
using Skoruba.IdentityServer4.STS.Identity.Helpers;
using Skoruba.IdentityServer4.STS.Identity.Helpers.Localization;
using Skoruba.IdentityServer4.STS.Identity.ViewModels.Account;

using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Http;
using IdentityModel.Client;
using System.Web;
using System.Text.Json;
using System.Collections.Generic;
using Newtonsoft.Json;
using Skoruba.IdentityServer4.STS.Identity.ViewModels.ExternalLogin;
using Microsoft.EntityFrameworkCore;

namespace Skoruba.IdentityServer4.STS.Identity.Controllers
{
    [SecurityHeaders]
    [Authorize]
    public class UserController<TUser, TKey> : Controller
        where TUser : IdentityUser<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        private readonly UserResolver<TUser> _userResolver;
        private readonly UserManager<TUser> _userManager;
        private readonly SignInManager<TUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly IEmailSender _emailSender;
        private readonly IGenericControllerLocalizer<AccountController<TUser, TKey>> _localizer;
        private readonly LoginConfiguration _loginConfiguration;
        private readonly RegisterConfiguration _registerConfiguration;
        private readonly IHttpClientFactory _clientFactory;
        private readonly IConfiguration _configuration;
        public UserController(
            UserResolver<TUser> userResolver,
            UserManager<TUser> userManager,
            SignInManager<TUser> signInManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IEmailSender emailSender,
            IGenericControllerLocalizer<AccountController<TUser, TKey>> localizer,
            LoginConfiguration loginConfiguration,
            RegisterConfiguration registerConfiguration,
            IHttpClientFactory clientFactory,
             IConfiguration configuration)
        {
            _userResolver = userResolver;
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _emailSender = emailSender;
            _localizer = localizer;
            _loginConfiguration = loginConfiguration;
            _registerConfiguration = registerConfiguration;
            _clientFactory = clientFactory;
            _configuration = configuration;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(CustomLoginModel model)
        {
            if (ModelState.IsValid)
            {
               
                    var cache = new DiscoveryCache(_configuration.GetValue<string>("BaseUrl"));

                var client = _clientFactory.CreateClient("IDS");

                var disco = await cache.GetAsync(); //await client.GetDiscoveryDocumentAsync(_configuration.GetValue<string>("BaseUrl"));
                if (disco.IsError)
                {
                    return BadRequest(disco.Error);
                }

                var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
                {
                    Address = disco.TokenEndpoint,

                    ClientId = "xframework_client",
                    ClientSecret = "secret",
                    Scope = "xframework_api openid offline_access profile email roles xframeworkid",
 
                    UserName = model.Username,
                    Password = model.Password
                });

                if (tokenResponse.IsError)
                {
                    return BadRequest(tokenResponse.Error);
                }
                
                return Ok(new{ access_token = tokenResponse.AccessToken, expires_in = tokenResponse.ExpiresIn, refresh_token = tokenResponse.RefreshToken  });


             /*
                var result = await _userManager.FindByNameAsync(model.Username);

                if (result != null && await _userManager.CheckPasswordAsync(result, model.Password))
                {
                    return Ok(tokenResponse);// Ok(new ProfileViewModel(result, tokenResponse));
                }*/
            }
            return BadRequest("Invalid username or password." + model.Username + model.Password);
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> LoginPhoneNo(CustomLoginPhoneNoModel model)
        {
            if (ModelState.IsValid)
            {
                var request = new HttpRequestMessage(HttpMethod.Get, _configuration.GetValue<string>("ValidateOtpUrl") + "?mobile=" + model.PhoneNo + "&transactionCode=" + model.TransactionCode + "&otp=" + model.Otp + "&secret=" + _configuration.GetValue<string>("UserAPISecret"));
                //request.Headers.Add("X-Validate-V3", new List<string>() { this.HttpContext.Request.Headers["X-Validate-V3"] });
                //request.Headers.Add("X-Validate-V2", new List<string>() { this.HttpContext.Request.Headers["X-Validate-V2"] });
                //request.Headers.Add("X-Forwarded-For", new List<string>() { this.HttpContext.Request.Headers["X-Forwarded-For"] });
                //request.Headers.Add("X-Forwarded-For-IP", new List<string>() { this.HttpContext.Request.Headers["X-Forwarded-For"] });

                var client1 = _clientFactory.CreateClient();

                var response = await client1.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    var user = await _userManager.Users.FirstOrDefaultAsync(x => x.PhoneNumber == model.PhoneNo);
                    if (user == null)
                    {
                        return BadRequest("Invalid phone no");
                    }

                    var cache = new DiscoveryCache(_configuration.GetValue<string>("BaseUrl"));

                    var client = _clientFactory.CreateClient("IDS");

                    var disco = await cache.GetAsync(); //await client.GetDiscoveryDocumentAsync(_configuration.GetValue<string>("BaseUrl"));
                    if (disco.IsError)
                    {
                        return BadRequest(disco.Error);
                    }

                    var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
                    {
                        Address = disco.TokenEndpoint,

                        ClientId = "xframework_client",
                        ClientSecret = "secret",
                        Scope = "xframework_api openid offline_access profile email roles xframeworkid",

                        UserName = user.UserName,
                        //Password = user.Password
                    });

                    if (tokenResponse.IsError)
                    {
                        return BadRequest(tokenResponse.Error);
                    }

                    return Ok(new { access_token = tokenResponse.AccessToken, expires_in = tokenResponse.ExpiresIn, refresh_token = tokenResponse.RefreshToken });


                    /*
                       var result = await _userManager.FindByNameAsync(model.Username);

                       if (result != null && await _userManager.CheckPasswordAsync(result, model.Password))
                       {
                           return Ok(tokenResponse);// Ok(new ProfileViewModel(result, tokenResponse));
                       }*/
                }
            
            else
            {
                return BadRequest(response.ReasonPhrase);
            }
        }
            return BadRequest("Invalid phone no or otp." + model.PhoneNo );
        }



        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Token(string refreshToken)
        {
            if (!string.IsNullOrWhiteSpace(refreshToken))
            {
                var cache = new DiscoveryCache(_configuration.GetValue<string>("BaseUrl"));

                var client = _clientFactory.CreateClient("IDS");

                var disco = await cache.GetAsync(); //await client.GetDiscoveryDocumentAsync(_configuration.GetValue<string>("BaseUrl"));
                if (disco.IsError)
                {
                    return BadRequest(disco.Error);
                }
                var tokenResponse = await client.RequestRefreshTokenAsync(new RefreshTokenRequest
                {
                    Address = disco.TokenEndpoint,

                    ClientId = "xframework_client",
                    ClientSecret = "secret",
                    Scope = "xframework_api openid offline_access profile email roles xframeworkid",
                    RefreshToken = refreshToken
                });

                if (tokenResponse.IsError)
                {
                    return BadRequest(tokenResponse.Error);
                }

                return Ok(new { access_token = tokenResponse.AccessToken, expires_in = tokenResponse.ExpiresIn, refresh_token = tokenResponse.RefreshToken });
            }
            return BadRequest("Invalid username or password.");
        }



        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Logout(string accessToken)
        {
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                var cache = new DiscoveryCache(_configuration.GetValue<string>("BaseUrl"));

                var client = _clientFactory.CreateClient("IDS");

                var disco = await cache.GetAsync(); //await client.GetDiscoveryDocumentAsync(_configuration.GetValue<string>("BaseUrl"));
                if (disco.IsError)
                {
                    return BadRequest(disco.Error);
                }

                var tokenResponse = await client.RevokeTokenAsync(new TokenRevocationRequest
                {
                    Address = disco.RevocationEndpoint,
                    ClientId = "xframework_client",
                    ClientSecret = "secret",

                    Token = accessToken
                });

                if (tokenResponse.IsError)
                {
                    return BadRequest(tokenResponse.Error);
                }

                return Ok("Success");
            }
            return BadRequest("Invaid token");
        }

        
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return BadRequest("Invalid userid or code");
            }
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest("Invalid userid or code");
            }
            //code = HttpUtility.UrlDecode(code);
            var result = await _userManager.ConfirmEmailAsync(user, code);

            if (result.Succeeded)
            {
                return Ok("Success");
            }

            return BadRequest("Invalid userid or code");
        }

    
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null) //|| !await _userManager.IsEmailConfirmedAsync(user)
                {
                    ModelState.AddModelError(string.Empty, _localizer["EmailNotFound"]);

                    return BadRequest(model);
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                code = HttpUtility.UrlEncode(code);
                var callbackUrl = _configuration["ResetPasswordUrl"] + "?userId=" + user.Id + "&code=" + code;

                await _emailSender.SendEmailAsync(model.Email, _localizer["ResetPasswordTitle"], _localizer["ResetPasswordBody", HtmlEncoder.Default.Encode(callbackUrl)]);


                return Ok("Success");
            }

            return BadRequest(model);
        }

     
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordByUserIdViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(model);
            }
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                return BadRequest("Invalid email");
            }
            var result = await _userManager.ResetPasswordAsync(user, HttpUtility.UrlDecode(model.Code), model.Password);
            if (result.Succeeded)
            {
                return Ok("Success");
            }

            var result1 = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result1.Succeeded)
            {
                return Ok("Success");
            }

            AddErrors(result);

            return BadRequest(result);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> SendOtp(string Mobile)
        {

            if (Mobile.Length!=10) return BadRequest("Mobile not 10 digitgs");


            var request = new HttpRequestMessage(HttpMethod.Get, _configuration.GetValue<string>("ValidateOtpUrl") + "?mobile=" + Mobile + "&secret=" + _configuration.GetValue<string>("UserAPISecret"));
            request.Headers.Add("X-Validate-V3", new List<string>() { this.HttpContext.Request.Headers["X-Validate-V3"] });
            request.Headers.Add("X-Validate-V2", new List<string>() { this.HttpContext.Request.Headers["X-Validate-V2"] });
            request.Headers.Add("X-Forwarded-For", new List<string>() { this.HttpContext.Request.Headers["X-Forwarded-For"] });
            request.Headers.Add("X-Forwarded-For-IP", new List<string>() { this.HttpContext.Request.Headers["X-Forwarded-For"] });

            var client1 = _clientFactory.CreateClient();

            var response = await client1.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                return Ok(response.ReasonPhrase);
            }
            // If we got this far, something failed, redisplay form
            return BadRequest(response.ReasonPhrase);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterWithPhoneNoViewModel model)
        {
            
            if (!ModelState.IsValid) return BadRequest(model);


          
            var request = new HttpRequestMessage(HttpMethod.Get, _configuration.GetValue<string>("ValidateOtpUrl") + "?mobile=" + model.PhoneNo + "&transactionCode=" + model.TransactionCode + "&otp=" + model.Otp + "&secret=" + _configuration.GetValue<string>("UserAPISecret"));
            //request.Headers.Add("X-Validate-V3", new List<string>() { this.HttpContext.Request.Headers["X-Validate-V3"] });
            //request.Headers.Add("X-Validate-V2", new List<string>() { this.HttpContext.Request.Headers["X-Validate-V2"] });
            //request.Headers.Add("X-Forwarded-For", new List<string>() { this.HttpContext.Request.Headers["X-Forwarded-For"] });
            //request.Headers.Add("X-Forwarded-For-IP", new List<string>() { this.HttpContext.Request.Headers["X-Forwarded-For"] });

            var client1 = _clientFactory.CreateClient();

            var response = await client1.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                if (model.SSOType=="facebook")
                {
                    var rr = await Facebook(new FacebookAuthViewModel() { Code = model.SSOCode, AccessToken = model.SSOAccessToken });
                    if (rr == null)
                    {
                        return BadRequest("Invalid facebook token.");
                    }
                }

                var user = new TUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    PhoneNumber = model.PhoneNo,
                    PhoneNumberConfirmed = true
                };

                var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                var requestq = new HttpRequestMessage(HttpMethod.Get, _configuration.GetValue<string>("UserAPIUrl") + "?id=" + user.Id + "&email=" + model.Email + "&mobile=" + model.PhoneNo + "&secret=" + _configuration.GetValue<string>("UserAPISecret"));
                //request.Headers.Add("Accept", "application/vnd.github.v3+json");
                //request.Headers.Add("User-Agent", "HttpClientFactory-Sample");

               
                var response1 = await client1.SendAsync(requestq);

                if (response1.IsSuccessStatusCode)
                {
                    using var responseStream = await response1.Content.ReadAsStreamAsync();

                    var profile = await System.Text.Json.JsonSerializer.DeserializeAsync<RegisterResponseViewModel>(responseStream);

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = HttpUtility.UrlEncode(code);
                    var callbackUrl = _configuration["ConfirmEmailUrl"] + "?userId=" + user.Id + "&code=" + code;

                    await _emailSender.SendEmailAsync(model.Email, _localizer["ConfirmEmailTitle"], _localizer["ConfirmEmailBody", HtmlEncoder.Default.Encode(callbackUrl)]);
                    //await _signInManager.SignInAsync(user, isPersistent: false);

                    var cache = new DiscoveryCache(_configuration.GetValue<string>("BaseUrl"));

                    var client = _clientFactory.CreateClient("IDS");

                    var disco = await cache.GetAsync(); //await client.GetDiscoveryDocumentAsync(_configuration.GetValue<string>("BaseUrl"));
                    if (disco.IsError)
                    {
                        await _userManager.DeleteAsync(user);
                        return StatusCode(504);
                    }
                    
                    string[] roles = new string[]{"User","Vendor"};
                    await _userManager.AddToRolesAsync(user, roles);
                    await _userManager.AddClaimAsync(user, new Claim("xframeworkid", profile.id.ToString()));

                    var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
                    {
                        Address = disco.TokenEndpoint, 

                        ClientId = "xframework_client",
                        ClientSecret = "secret",
                        Scope = "xframework_api openid offline_access profile email roles xframeworkid",
                        UserName = model.Email,
                        Password = model.Password
                    });

                    if (tokenResponse.IsError)
                    {
                        await _userManager.DeleteAsync(user);
                        return StatusCode(504);
                    }

                    profile.accessToken = tokenResponse.AccessToken;
                    profile.expiresIn = tokenResponse.ExpiresIn.ToString();
                    profile.refreshToken = tokenResponse.RefreshToken;
                    return Ok(new {accessToken = tokenResponse.AccessToken, expiresIn = tokenResponse.ExpiresIn,refreshToken = tokenResponse.RefreshToken});
                }
                else
                {
                    await _userManager.DeleteAsync(user);
                    return StatusCode(504);
                }

            }

            AddErrors(result);

            // If we got this far, something failed, redisplay form
            return BadRequest(result);
            }
            // If we got this far, something failed, redisplay form
            return BadRequest(response.ReasonPhrase);

        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> SendEmailConfirmationLink(EmailViewModel model)
        {

            if (!ModelState.IsValid) return BadRequest(model);


            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return BadRequest("Invalid email");
            }

           
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = HttpUtility.UrlEncode(code);
            var callbackUrl = _configuration["ConfirmEmailUrl"] + "?userId=" + user.Id + "&code=" + code;

            await _emailSender.SendEmailAsync(model.Email, _localizer["ConfirmEmailTitle"], _localizer["ConfirmEmailBody", HtmlEncoder.Default.Encode(callbackUrl)]);
            //await _signInManager.SignInAsync(user, isPersistent: false);

            return Ok("Success");
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Validate(string accessToken)
        {
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                var cache = new DiscoveryCache(_configuration.GetValue<string>("BaseUrl"));

                var client = _clientFactory.CreateClient("IDS");

                var disco = await cache.GetAsync(); //await client.GetDiscoveryDocumentAsync(_configuration.GetValue<string>("BaseUrl"));
                if (disco.IsError)
                {
                    return BadRequest(disco.Error);
                }

                var tokenResponse = await client.GetUserInfoAsync(new UserInfoRequest
                {
                    Address = disco.UserInfoEndpoint,
                    Token = accessToken
                });


                if (tokenResponse.IsError)
                {
                    return BadRequest(tokenResponse.Error);
                }

                return Ok(tokenResponse);
            }
            return BadRequest("Invaid token");
        }


        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/
        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null)
            {
                // this is meant to short circuit the UI and only trigger the one external IdP
                return new LoginViewModel
                {
                    EnableLocalLogin = false,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                    LoginResolutionPolicy = _loginConfiguration.ResolutionPolicy,
                    ExternalProviders = new ExternalProvider[] { new ExternalProvider { AuthenticationScheme = context.IdP } }
                };
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                LoginResolutionPolicy = _loginConfiguration.ResolutionPolicy,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

        // POST api/externalauth/facebook
        private async Task<FacebookUserData> Facebook(FacebookAuthViewModel model)
        {
            var externalProviderConfiguration = _configuration.GetSection(nameof(ExternalProvidersConfiguration)).Get<ExternalProvidersConfiguration>();

            HttpClient Client = _clientFactory.CreateClient();

            // 1.generate an app access token
            var appAccessTokenResponse = await Client.GetStringAsync($"https://graph.facebook.com/oauth/access_token?client_id={externalProviderConfiguration.FacebookClientId}&client_secret={externalProviderConfiguration.FacebookClientSecret}&grant_type=client_credentials");
            var appAccessToken = JsonConvert.DeserializeObject<FacebookAppAccessToken>(appAccessTokenResponse);
          

            if (!string.IsNullOrWhiteSpace(model.Code))
            {
                // 1.generate an app access token
                var userAccessTokenResponse = await Client.GetStringAsync($"https://graph.facebook.com/v7.0/oauth/access_token?client_id={externalProviderConfiguration.FacebookClientId}&redirect_uri={externalProviderConfiguration.FacebookRedirectUri}&client_secret={externalProviderConfiguration.FacebookClientSecret}&code={model.Code}");
                var userAccessToken = JsonConvert.DeserializeObject<FacebookAppAccessToken>(appAccessTokenResponse);
                model.AccessToken = userAccessToken.AccessToken;
            }

            if (!string.IsNullOrWhiteSpace(model.AccessToken))
            {

                // 2. validate the user access token
                var userAccessTokenValidationResponse = await Client.GetStringAsync($"https://graph.facebook.com/debug_token?input_token={model.AccessToken}&access_token={appAccessToken.AccessToken}");
                var userAccessTokenValidation = JsonConvert.DeserializeObject<FacebookUserAccessTokenValidation>(userAccessTokenValidationResponse);

                if (!userAccessTokenValidation.Data.IsValid)
                {
                    return null;
                }
            }

            // 3. we've got a valid token so we can request user data from fb
            var userInfoResponse = await Client.GetStringAsync($"https://graph.facebook.com/v2.8/me?fields=id,email,first_name,last_name,name,gender,locale,birthday,picture&access_token={model.AccessToken}");
            var userInfo = JsonConvert.DeserializeObject<FacebookUserData>(userInfoResponse);

            return userInfo;
        }

        // POST api/externalauth/facebook
        private async Task<GoogleUserData> Google(GoogleAuthViewModel model)
        {
            /*
            // 1.generate an app token id
            var userAccessTokenValidationResponse = await Client.GetStringAsync($"https://oauth2.googleapis.com/tokeninfo?id_token={model.id_token}");
            var userInfo = JsonConvert.DeserializeObject<GoogleUserData>(userAccessTokenValidationResponse);

            if (!userInfo.IsVerified || _googleAuthSettingsAccessor.ClientId != userInfo.ClientId)
            {
                return BadRequest(Errors.AddErrorToModelState("login_failure", "Invalid google id token.", ModelState));
            }

            // 2. ready to create the local user account (if necessary) and jwt
            var user = await _userManager.FindByEmailAsync(userInfo.Email);

            if (user == null)
            {
                var appUser = new AppUser
                {
                    FirstName = userInfo.FirstName,
                    LastName = userInfo.LastName,
                    GoogleId = userInfo.Id,
                    Email = userInfo.Email,
                    UserName = userInfo.Email,
                    PictureUrl = userInfo.Picture
                };

                var result = await _userManager.CreateAsync(appUser, Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Substring(0, 8));

                if (!result.Succeeded) return new BadRequestObjectResult(Errors.AddErrorsToModelState(result, ModelState));

                await _appDbContext.Customers.AddAsync(new Customer { IdentityId = appUser.Id, Location = "", Locale = userInfo.Locale, Gender = "" });
                await _appDbContext.SaveChangesAsync();
            }

            // generate the jwt for the local user...
            var localUser = await _userManager.FindByNameAsync(userInfo.Email);

            if (localUser == null)
            {
                return BadRequest(Errors.AddErrorToModelState("login_failure", "Failed to create local user account.", ModelState));
            }

            var jwt = await Tokens.GenerateJwt(_jwtFactory.GenerateClaimsIdentity(localUser.UserName, localUser.Id),
              _jwtFactory, localUser.UserName, _jwtOptions, new JsonSerializerSettings { Formatting = Formatting.Indented });
            */
            return null;
        }
    }
}