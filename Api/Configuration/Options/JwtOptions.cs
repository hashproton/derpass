using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Api.Configuration.Options;

public class JwtOptions
{
    [Required]
    public string Secret { get; set; } = null!;
    
    [Required]
    public string Issuer { get; set; } = null!;
    
    [Required]
    public string Audience { get; set; } = null!;

    [Required]
    public RefreshTokenOptions RefreshToken { get; set; } = null!;

    public SymmetricSecurityKey SymmetricSecurityKey => new(Encoding.UTF8.GetBytes(Secret));

    public class RefreshTokenOptions
    {
        [Required]
        public int ExpiryInDays { get; set; }
    }
}