using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Api.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Api;

public static class DerpassIdentity
{
    public const string Schema = "Derpass";

    public const string JwtKey
        = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAV9hjmHe1FMgVx0nt1NRNuE0r+e+HoSViw3ZO9Gv7b/VCyGxL7LamVbnKUgjdIvyb2MkKHZvULtUEhzAyKgRqJPgBqVwzUQ2IIV";

    public static IdentityBuilder AddIdentityDerpassServices(this IServiceCollection services) =>
        services.AddIdentityDerpassServices(_ =>
        {
        });

    public static IdentityBuilder AddIdentityDerpassServices(
        this IServiceCollection services,
        Action<IdentityOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services
            .AddAuthentication(Schema)
            .AddScheme<AuthenticationSchemeOptions, CompositeIdentityHandler>(Schema, null);

        return services.AddIdentityCore<User>(configure)
            .AddApiEndpoints();
    }
    
    private sealed class CompositeIdentityHandler(
        ApplicationDbContext context,
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : SignInAuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        private string? GetJwtBearerTokenOrNull() =>
            Context.Request.Headers["Authorization"].FirstOrDefault()?.StartsWith("Bearer ") == true
                ? Context.Request.Headers["Authorization"].FirstOrDefault()?.Substring("Bearer ".Length)
                : null;

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var token = GetJwtBearerTokenOrNull();
            if (token is null)
            {
                return AuthenticateResult.NoResult();
            }
            
            var parsedToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
            
            var userId = parsedToken.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value;
            var jti = Guid.Parse(parsedToken.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value);
            
            var isTokenValid = await Context.RequestServices.GetRequiredService<ApplicationDbContext>()
                .RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Jti == jti && rt.UserId == userId);

            if (isTokenValid is null)
            {
                return AuthenticateResult.Fail("Token is invalid");
            }
            
            var user = await Context.RequestServices.GetRequiredService<UserManager<User>>().FindByIdAsync(userId);
            if (user is null)
            {
                return AuthenticateResult.Fail("User not found");
            }
            
            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, userId),
                new(JwtRegisteredClaimNames.Jti, jti.ToString()),
            };
            
            var roles = await Context.RequestServices.GetRequiredService<UserManager<User>>().GetRolesAsync(user);
            
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
            
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            
            var principal = new ClaimsPrincipal(identity);
            
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            
            return AuthenticateResult.Success(ticket);
        }

        protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
        {
            var tokens = await JwtBearerToken.GenerateToken(user, Context.RequestServices);
            var response = new TokenResponses
            {
                AccessToken = tokens.AccessToken,
                RefreshToken = tokens.RefreshToken
            };

            Logger.AuthenticationSchemeSignedIn(Scheme.Name);

            await Context.Response.WriteAsJsonAsync(response, TokenResponsesJsonSerializerContext.Default.TokenResponses);
        }

        protected override Task HandleSignOutAsync(AuthenticationProperties? properties)
        {
            Logger.AuthenticationSchemeSignedOut(Scheme.Name);

            return Task.CompletedTask;
        }
    }
}

