using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Api.Configuration.Options;
using Api.Entities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Api.Configuration;

public class ConfigureJwtBearerOptions(IOptions<JwtOptions> options)
    : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly JwtOptions _options = options?.Value ?? throw new ArgumentNullException(nameof(options));

    public void Configure(JwtBearerOptions options)
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _options.SymmetricSecurityKey,
            ValidateIssuer = true,
            ValidIssuer = _options.Issuer,
            ValidateAudience = true,
            ValidAudience = _options.Audience,
            ClockSkew = TimeSpan.Zero
        };
        
        options.Events = new JwtBearerEvents
        {
            OnForbidden = _ => Task.CompletedTask,
            OnTokenValidated = async context =>
            {
                var userId = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
                if (userId is null)
                {
                    context.Fail("Unauthorized");
                    return;
                }

                var jti = context.Principal?.FindFirstValue(JwtRegisteredClaimNames.Jti);
                if (!Guid.TryParse(jti, out var jtiGuid))
                {
                    context.Fail("Unauthorized");
                    return;
                }

                var dbContext = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
                var refreshToken = await dbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Jti == jtiGuid && x.UserId == userId);
                if (refreshToken == null || refreshToken.IsRevoked || refreshToken.IsExpired)
                {
                    context.Fail("Unauthorized");
                    return;
                }

                var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<User>>();
                var user = await userManager.FindByIdAsync(userId);
                if (user is null)
                {
                    context.Fail("Unauthorized");
                    return;
                }

                if (context.Principal is not { } principal)
                {
                    context.Fail("Unauthorized");
                    return;
                }

                var identity = (ClaimsIdentity)principal.Identity!;
                var roles = await userManager.GetRolesAsync(user);
                foreach (var role in roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }

                context.Success();
            },
            OnAuthenticationFailed = context =>
            {
                if (context.Exception is SecurityTokenExpiredException)
                {
                    // No need to add custom headers since WWW-Authenticate is already set
                }

                return Task.CompletedTask;
            },
            OnChallenge = _ => Task.CompletedTask,
        };
    }

    public void Configure(string? name, JwtBearerOptions options)
    {
        Configure(options);
    }
}