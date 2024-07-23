using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Api.Configuration.Options;
using Api.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Api.Utils;

internal static class JwtBearerToken
{
    public static async Task<TokenResponses> GenerateToken(string userId, IServiceProvider sp)
    {
        var options = sp.GetRequiredService<IOptions<JwtOptions>>().Value;

        var tokenHandler = new JwtSecurityTokenHandler();

        var jti = Guid.NewGuid();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,
            Audience = options.Audience,
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, jti.ToString()),
            }),
            Expires = DateTime.UtcNow.AddHours(12),
            SigningCredentials = new SigningCredentials(options.SymmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);

        var refreshToken = new RefreshToken
        {
            Jti = jti,
            UserId = userId,
            Expires = DateTime.UtcNow.AddDays(options.RefreshToken.ExpiryInDays)
        };
        
        sp.GetRequiredService<ApplicationDbContext>().RefreshTokens.Add(refreshToken);
        await sp.GetRequiredService<ApplicationDbContext>().SaveChangesAsync();

        return new()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Id.ToString()
        };
    }
}