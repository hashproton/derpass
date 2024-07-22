using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Api.Utils;

internal static class JwtBearerToken
{
    public static async Task<TokenResponses> GenerateToken(ClaimsPrincipal user, IServiceProvider sp)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(DerpassIdentity.JwtKey));
        var jti = Guid.NewGuid();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value),
                new Claim(JwtRegisteredClaimNames.Jti, jti.ToString()),
            }),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);

        var refreshToken = new RefreshToken
        {
            Jti = jti,
            UserId = user.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value
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