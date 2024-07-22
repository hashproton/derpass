using Microsoft.AspNetCore.Identity;

namespace Api;

public class User : IdentityUser
{
    public ICollection<RefreshToken> RefreshTokens { get; set; } = [];
}