using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace Api.Endpoints;

public static class IdentityEndpointsExtension
{
    public static RouteGroupBuilder MapIdentityApi(this RouteGroupBuilder group)
    {
        group.MapPost("/login", Login);

        return group;
    }

    private static async Task<Results<Ok<TokenResponses>, EmptyHttpResult, ProblemHttpResult>> Login(
        [FromBody] LoginRequest login,
        [FromQuery] bool? useCookies,
        [FromQuery] bool? useSessionCookies,
        [FromServices] IServiceProvider sp)
    {
        var signInManager = sp.GetRequiredService<SignInManager<User>>();

        signInManager.AuthenticationScheme = DerpassIdentity.Schema;

        var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, false, lockoutOnFailure: true);

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

        return TypedResults.Empty;
    }
}

