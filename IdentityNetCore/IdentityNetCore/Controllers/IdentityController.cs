using IdentityNetCore.Models;
using IdentityNetCore.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.Security.Claims;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public IdentityController(UserManager<IdentityUser> userManager, IEmailSender emailSender, 
            SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }
        public IActionResult Signup()
        {
            var model = new SignupViewModel() { Role = "Member" };
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (!(await _roleManager.RoleExistsAsync(model.Role)))
                {
                    var roleResult = await _roleManager.CreateAsync(new IdentityRole { Name = model.Role });
                    if (!roleResult.Succeeded)
                    {
                        var errors = roleResult.Errors.Select(s => s.Description);
                        ModelState.AddModelError("Role", string.Join(",", errors));
                        return View(model);
                    }
                }
                if ((await _userManager.FindByEmailAsync(model.Email)) == null)
                {
                    var user = new IdentityUser
                    {
                        Email = model.Email,
                        UserName = model.Email
                    };
                    var result = await _userManager.CreateAsync(user, model.Password);

                    user = await _userManager.FindByEmailAsync(model.Email);
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    if (result.Succeeded)
                    {
                        var claim = new Claim("Department", model.Department);
                        await _userManager.AddClaimAsync(user, claim);
                        await _userManager.AddToRoleAsync(user, model.Role);
                        var confirmationLink =  Url.ActionLink("ConfirmEmail", "Identity", new
                        {
                            userId = user.Id,
                            @token = token
                        });
                        await _emailSender.SendEmailAsync("info@mydomain.com", user.Email, "Confirm your email address", confirmationLink);
                        return RedirectToAction("Signin");
                    }
                    ModelState.AddModelError("Signup", string.Join("", result.Errors.Select(x => x.Description)));
                    return View(model);
                }
            }

            return View(model);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        { 
            var user = await _userManager.FindByIdAsync(userId);
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return RedirectToAction("Signin");
            }
            return new NotFoundResult();
        }

        [Authorize]
        public async Task<IActionResult> MFASetup()
        {
            const string provider = "aspnetidentity";
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var qrCodeUrl = $"otpauth://totp/{provider}:{user.Email}?secret={token}&issuer={provider}&digits=6";

            var model = new MFAViewModel { Token = token, QRCodeUrl = qrCodeUrl };
            return View(model);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> MFASetup(MFAViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user,
                    _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                else
                    ModelState.AddModelError("Verify", "Your MFA code could not be validated.");
            }

            return View(model);
        }

        public IActionResult Signin()
        {
            
            return View(new SigninViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> Signin(SigninViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RemeberMe, false);
                if (result.RequiresTwoFactor) return RedirectToAction("MFACheck");
                if (result.Succeeded)
                {
                    var userName = HttpContext.User.Identity.Name;
                    var user = await _userManager.FindByEmailAsync(userName);
                    //var userClaims = await _userManager.GetClaimsAsync(user);

                    //if (!userClaims.Any(x => x.Type == "Department"))
                    //{
                    //    ModelState.AddModelError("Claim", "User not in the right department");
                    //    return View(model);
                    //}

                    if (await _userManager.IsInRoleAsync(user, "Member"))
                    {
                        return RedirectToAction("Member", "Home");
                    }

                    if (await _userManager.IsInRoleAsync(user, "Admin"))
                    {
                        return RedirectToAction("Admin", "Home");
                    }

                    return RedirectToAction("Index", "Home");
                } else
                {
                    ModelState.AddModelError("Login", "Cannot login");
                    return View(model);
                }
            } else
            {
                return View(model);
            }
        }

        public IActionResult MFACheck()
        {
            return View(new MNFACheckViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> MFACheck(MNFACheckViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, false, false);
                if (result.Succeeded) return RedirectToAction("Index", "Home", null);
            }

            return View(model);
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        public async Task<IActionResult> Signout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Signin", "Identity");
        }
    }
}
