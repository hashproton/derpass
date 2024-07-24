using System.Diagnostics;
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
        
        var manageGroup = group.MapGroup("/manage");
        manageGroup.MapPost("/2fa", TwoFactor);

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

        var result = await signInManager.PasswordSignInAsync(existingUser, login.Password, false, true);
        if (result.RequiresTwoFactor)
        {
            if (!string.IsNullOrEmpty(login.TwoFactorCode))
            {
                result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode,
                    false,
                    rememberClient: false);
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
        TimeProvider timeProvider,
        IServiceProvider sp)
    {
        var userId = context?.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId is null)
        {
            return TypedResults.Problem("Unauthorized", statusCode: StatusCodes.Status401Unauthorized);
        }

        var refreshToken = await db.RefreshTokens.FirstOrDefaultAsync(rt =>
            rt.Id == Guid.Parse(request.RefreshToken) && rt.UserId == userId);
        if (refreshToken is null)
        {
            return TypedResults.Problem("Invalid refresh token", statusCode: StatusCodes.Status401Unauthorized);
        }

        if (refreshToken.IsRevoked || refreshToken.IsExpired)
        {
            return TypedResults.Problem("Refresh token is revoked or expired",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        refreshToken.Revoked = timeProvider.GetUtcNow().DateTime;
        db.RefreshTokens.Update(refreshToken);
        await db.SaveChangesAsync();

        var token = await JwtBearerToken.GenerateToken(userId, sp);

        return TypedResults.Ok(token);
    }

    private static async Task<Results<Ok<TwoFactorResponse>, ValidationProblem, NotFound>> TwoFactor(
        ClaimsPrincipal claimsPrincipal,
        [FromBody] TwoFactorRequest tfaRequest,
        [FromServices] SignInManager<User> signInManager)
    {
        var userManager = signInManager.UserManager;
        if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
        {
            return TypedResults.NotFound();
        }

        if (tfaRequest.Enable == true)
        {
            if (tfaRequest.ResetSharedKey)
            {
                return CreateValidationProblem(
                    "CannotResetSharedKeyAndEnable",
                    "Resetting the 2fa shared key must disable 2fa until a 2fa token based on the new shared key is validated.");
            }

            if (string.IsNullOrEmpty(tfaRequest.TwoFactorCode))
            {
                return CreateValidationProblem(
                    "RequiresTwoFactor",
                    "No 2fa token was provided by the request. A valid 2fa token is required to enable 2fa.");
            }

            if (!await userManager.VerifyTwoFactorTokenAsync(user,
                    userManager.Options.Tokens.AuthenticatorTokenProvider,
                    tfaRequest.TwoFactorCode))
            {
                return CreateValidationProblem(
                    "InvalidTwoFactorCode",
                    "The 2fa token provided by the request was invalid. A valid 2fa token is required to enable 2fa.");
            }

            await userManager.SetTwoFactorEnabledAsync(user, true);
        }
        else if (tfaRequest.Enable == false || tfaRequest.ResetSharedKey)
        {
            await userManager.SetTwoFactorEnabledAsync(user, false);
        }

        if (tfaRequest.ResetSharedKey)
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
        }

        string[]? recoveryCodes = null;
        if (tfaRequest.ResetRecoveryCodes ||
            (tfaRequest.Enable == true && await userManager.CountRecoveryCodesAsync(user) == 0))
        {
            var recoveryCodesEnumerable = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            recoveryCodes = recoveryCodesEnumerable?.ToArray();
        }

        if (tfaRequest.ForgetMachine)
        {
            await signInManager.ForgetTwoFactorClientAsync();
        }

        var key = await userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            key = await userManager.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(key))
            {
                throw new NotSupportedException("The user manager must produce an authenticator key after reset.");
            }
        }
        
        const string authenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        return TypedResults.Ok(new TwoFactorResponse
        {
            SharedKey = key,
            RecoveryCodes = recoveryCodes,
            RecoveryCodesLeft = recoveryCodes?.Length ?? await userManager.CountRecoveryCodesAsync(user),
            IsTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user),
            IsMachineRemembered = await signInManager.IsTwoFactorClientRememberedAsync(user),
            QRCodeUrl = string.Format(authenticatorUriFormat, "Scalizup.Derpass", user.Email, key)
        });
    }
    
    private static ValidationProblem CreateValidationProblem(string errorCode, string errorDescription) =>
        TypedResults.ValidationProblem(new Dictionary<string, string[]> {
            { errorCode, [errorDescription] }
        });
    
    private static ValidationProblem CreateValidationProblem(IdentityResult result)
    {
        // We expect a single error code and description in the normal case.
        // This could be golfed with GroupBy and ToDictionary, but perf! :P
        Debug.Assert(!result.Succeeded);
        var errorDictionary = new Dictionary<string, string[]>(1);

        foreach (var error in result.Errors)
        {
            string[] newDescriptions;

            if (errorDictionary.TryGetValue(error.Code, out var descriptions))
            {
                newDescriptions = new string[descriptions.Length + 1];
                Array.Copy(descriptions, newDescriptions, descriptions.Length);
                newDescriptions[descriptions.Length] = error.Description;
            }
            else
            {
                newDescriptions = [error.Description];
            }

            errorDictionary[error.Code] = newDescriptions;
        }

        return TypedResults.ValidationProblem(errorDictionary);
    }
}

public sealed class TwoFactorResponse
{
    /// <summary>
    /// The shared key generally for TOTP authenticator apps that is usually presented to the user as a QR code.
    /// </summary>
    public required string SharedKey { get; init; }

    /// <summary>
    /// The number of unused <see cref="RecoveryCodes"/> remaining.
    /// </summary>
    public required int RecoveryCodesLeft { get; init; }

    /// <summary>
    /// The recovery codes to use if the <see cref="SharedKey"/> is lost. This will be omitted from the response unless
    /// <see cref="TwoFactorRequest.ResetRecoveryCodes"/> was set or two-factor was enabled for the first time.
    /// </summary>
    public string[]? RecoveryCodes { get; init; }

    /// <summary>
    /// Whether or not two-factor login is required for the current authenticated user.
    /// </summary>
    public required bool IsTwoFactorEnabled { get; init; }

    /// <summary>
    /// Whether or not the current client has been remembered by two-factor authentication cookies. This is always <see langword="false"/> for non-cookie authentication schemes.
    /// </summary>
    public required bool IsMachineRemembered { get; init; }

    /// <summary>
    /// QR code URL for the shared key.
    /// </summary>
    public  required string QRCodeUrl { get; init; }
}


public class RefreshTokenRequest
{
    public string RefreshToken { get; init; } = null!;
}