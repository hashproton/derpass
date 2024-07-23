using Microsoft.AspNetCore.Identity;

namespace Api.Entities;

public class User : IdentityUser
{
    public ICollection<RefreshToken> RefreshTokens { get; set; } = [];
}