namespace Api;

public class RefreshToken
{
    public Guid Id { get; set; }
    
    public Guid Jti { get; set; }
    public DateTime Expires { get; set; }
    
    public bool IsExpired => DateTime.UtcNow >= Expires;

    public DateTime? Revoked { get; set; }

    public bool IsRevoked => Revoked is not null;
    
    public User User { get; set; } = default!;
    public string UserId { get; set; } = default!;
}