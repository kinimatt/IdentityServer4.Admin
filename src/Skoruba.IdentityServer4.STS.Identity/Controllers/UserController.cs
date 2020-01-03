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
                    Address = disco.TokenEndpoint, //"https://demo.identityserver.io/connect/token",

                    ClientId = "xframework_client",
                    ClientSecret = "secret",
                    Scope = "xframework_api openid offline_access",

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
            return BadRequest("Invalid username or password.");
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
                var client = _clientFactory.CreateClient("IDS");

                var disco = await client.GetDiscoveryDocumentAsync("https://localhost:5001");
                if (disco.IsError)
                {
                    return BadRequest(disco.Error);
                }
                var tokenResponse = await client.RequestRefreshTokenAsync(new RefreshTokenRequest
                {
                    Address = disco.TokenEndpoint,

                    ClientId = "xframework_client",
                    ClientSecret = "secret",
                    Scope = "xframework_api openid offline_access",

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
                var client = _clientFactory.CreateClient("IDS");

                var disco = await client.GetDiscoveryDocumentAsync("https://localhost:5001");
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

                if (user == null || !await _userManager.IsEmailConfirmedAsync(user))
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
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return BadRequest("Invalid email");
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return Ok("Success");
            }

            AddErrors(result);

            return BadRequest(result);
        }

     
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterWithoutUsernameViewModel model)
        {
            
            if (!ModelState.IsValid) return BadRequest(model);


            var user = new TUser
            {
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
              


                var request = new HttpRequestMessage(HttpMethod.Get, _configuration.GetValue<string>("UserAPIUrl") + "?");
                //request.Headers.Add("Accept", "application/vnd.github.v3+json");
                //request.Headers.Add("User-Agent", "HttpClientFactory-Sample");

                var client = _clientFactory.CreateClient();

                var response = await client.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    using var responseStream = await response.Content.ReadAsStreamAsync();

                    var profile = await JsonSerializer.DeserializeAsync<RegisterResponseViewModel>(responseStream);

                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = HttpUtility.UrlEncode(code);
                    var callbackUrl = _configuration["ConfirmEmailUrl"] + "?userId=" + user.Id + "&code=" + code;

                    await _emailSender.SendEmailAsync(model.Email, _localizer["ConfirmEmailTitle"], _localizer["ConfirmEmailBody", HtmlEncoder.Default.Encode(callbackUrl)]);
                    //await _signInManager.SignInAsync(user, isPersistent: false);


                    return Ok(profile);
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
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Validate(string accessToken)
        {
            if (!string.IsNullOrWhiteSpace(accessToken))
            {
                var client = _clientFactory.CreateClient("IDS");

                var disco = await client.GetDiscoveryDocumentAsync("https://localhost:5001");
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

                return Ok("Success");
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
    }
}