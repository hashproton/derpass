using System.Security.Claims;
using Api.Entities;
using Api.Utils;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Api.Endpoints;

public static class IdentityEndpointsExtension
{
    public static RouteGroupBuilder MapIdentityApi(this RouteGroupBuilder group)
    {
        group.MapPost("/login", Login);
        group.MapPost("/refresh", RefreshToken);

        return group;
    }

    private static async Task<Results<Ok<TokenResponses>, EmptyHttpResult, ProblemHttpResult>> Login(
        [FromBody] LoginRequest login,
        [FromQuery] bool? useCookies,
        [FromQuery] bool? useSessionCookies,
        [FromServices] SignInManager<User> signInManager,
        [FromServices] IServiceProvider sp)
    {
        var existingUser = await signInManager.UserManager.FindByEmailAsync(login.Email);
        if (existingUser is null)
        {
            return TypedResults.Problem("User not found", statusCode: StatusCodes.Status401Unauthorized);
        }
        
        var result = await signInManager.CheckPasswordSignInAsync(existingUser, login.Password, false);
        if (result.RequiresTwoFactor)
        {
            if (!string.IsNullOrEmpty(login.TwoFactorCode))
            {
                result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, false, rememberClient: false);
            }
            else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
            {
                result = await signInManager.TwoFactorRecoveryCodeSignInAsync(login.TwoFactorRecoveryCode);
            }
        }
        
        if (!result.Succeeded)
        {
            return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
        }

        var token = await JwtBearerToken.GenerateToken(existingUser.Id, sp);

        return TypedResults.Ok(token);
    }
    
    private static async Task<Results<Ok<TokenResponses>, EmptyHttpResult, ProblemHttpResult>> RefreshToken(
        [FromBody] RefreshTokenRequest request,
        HttpContext context,
        ApplicationDbContext db,
        IServiceProvider sp)
    {
        var userId = context?.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId is null)
        {
            return TypedResults.Problem("Unauthorized", statusCode: StatusCodes.Status401Unauthorized);
        }
        
        var refreshToken = await db.RefreshTokens.FirstOrDefaultAsync(rt => rt.Id == Guid.Parse(request.RefreshToken) && rt.UserId == userId);
        if (refreshToken is null)
        {
            return TypedResults.Problem("Invalid refresh token", statusCode: StatusCodes.Status401Unauthorized);
        }
        
        if (refreshToken.IsRevoked || refreshToken.IsExpired)
        {
            return TypedResults.Problem("Refresh token is revoked or expired", statusCode: StatusCodes.Status401Unauthorized);
        }
        
        refreshToken.Revoked = DateTime.UtcNow;
        
        var token = await JwtBearerToken.GenerateToken(userId, sp);

        return TypedResults.Ok(token);
    }
}

public class RefreshTokenRequest
{
    public string RefreshToken { get; set; } = null!;
}
