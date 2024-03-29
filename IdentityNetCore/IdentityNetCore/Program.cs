using AuthService.Models;
using IdentityNetCore.Data;
using IdentityNetCore.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationContext>(opt =>
{
    opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
});
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationContext>().AddDefaultTokenProviders();
builder.Services.Configure<IdentityOptions>(options =>
{

    options.Password.RequiredLength = 6;
    options.Password.RequireDigit = true;
    options.Password.RequireNonAlphanumeric = true;

    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);

    options.SignIn.RequireConfirmedAccount = true;
    options.SignIn.RequireConfirmedEmail = true;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Signin";
    options.AccessDeniedPath = "/Identity/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromHours(24);
});

builder.Services.AddAuthentication().AddFacebook(opt =>
{
    opt.AppId = builder.Configuration["FacebookLogInAppID"];
    opt.AppSecret = builder.Configuration["FacebookLogInAppSecret"];
});

builder.Services.AddSingleton<IEmailSender, MailJetEmailSender>();
builder.Services.AddAuthorization(option =>
{
    option.AddPolicy("Department", p =>
    {
        p.RequireClaim("Department", "Production").RequireRole("Admin");
    });
});




var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

// A Method For Getting a JWT Token 
app.MapPost("/auth", async (AuthModel model, SignInManager<IdentityUser> signInManager) =>
{
    var signInResult = await signInManager.PasswordSignInAsync(model.UserName, model.Password, false, true);
    if (signInResult.Succeeded)
    {
        var key = app.Configuration["EncryptionKey"] ?? "";
        var keyBytes = Encoding.ASCII.GetBytes(key);

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, model.UserName) }),
            Expires = DateTime.Now.AddDays(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256Signature),
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    // return 403
    throw new Exception("Signin was not successful");
});


// A Method For Validating a JWT Token 
app.MapGet("/validate", async (string token) =>
{
    var key = app.Configuration["EncryptionKey"] ?? "";
    var keyBytes = Encoding.ASCII.GetBytes(key);

    var tokenHandler = new JwtSecurityTokenHandler();
    var validateParameters = new TokenValidationParameters()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ValidateIssuer = false,
        ValidateAudience = false,
        RequireExpirationTime = true,
        ValidateLifetime = true,
    };

    var principal = await tokenHandler.ValidateTokenAsync(token, validateParameters);
    return principal.Claims;

});


app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
