using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Api;

public static class UsersEndpointsExtensions
{
    public static RouteGroupBuilder MapUsersApi(this RouteGroupBuilder group)
    {
        group.MapGet("/", GetAllUsers);
        group.MapGet("/{id:guid}", GetUserById);
        group.MapPost("/roles", AddUserToRole);
        group.MapDelete("/roles", RemoveUserFromRole);

        return group;
    }
    
    private static async Task<IResult> GetUserById(HttpContext
        context, [FromRoute] Guid id, [FromServices] UserManager<User> userManager)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        if (user is null)
        {
            return Results.NotFound();
        }
        
        var rolesAsync = await userManager.GetRolesAsync(user);

        return Results.Ok(new GetUserResponse(user.Id, user.UserName, user.Email, user.PhoneNumber, rolesAsync));
    }
    
    private static async Task<IResult> GetAllUsers(HttpContext context, [FromServices] UserManager<User> userManager)
    {
        var users = await userManager.Users.ToListAsync();

        var tasks = users.Select(async user =>
        {
            var roles = await userManager.GetRolesAsync(user);
            return new GetUserResponse(user.Id, user.UserName, user.Email, user.PhoneNumber, roles);
        });

        var response = await Task.WhenAll(tasks);

        return Results.Ok(response);
    }
    
    private static async Task<IResult> AddUserToRole(HttpContext context, [FromBody] AddUserToRoleRequest request, [FromServices] UserManager<User> userManager)
    {
        var user = await userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
        {
            return Results.NotFound();
        }

        var result = await userManager.AddToRoleAsync(user, request.Role);
        if (result.Succeeded)
        {
            return Results.Ok();
        }

        return Results.BadRequest(result.Errors);
    }
    
    private static async Task<IResult> RemoveUserFromRole(HttpContext context, [FromBody] AddUserToRoleRequest request, [FromServices] UserManager<User> userManager)
    {
        var user = await userManager.FindByIdAsync(request.UserId.ToString());
        if (user is null)
        {
            return Results.NotFound();
        }

        var result = await userManager.RemoveFromRoleAsync(user, request.Role);
        if (result.Succeeded)
        {
            return Results.Ok();
        }

        return Results.BadRequest(result.Errors);
    }
}

public record GetUserResponse(string Id, string UserName, string Email, string PhoneNumber, IEnumerable<string> Roles);