using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Api;

public static class RolesEndpointsExtension
{
    public static RouteGroupBuilder MapRolesApi(this RouteGroupBuilder group)
    {
        group.MapGet("/", GetAllRoles);
        group.MapPost("/", CreateRole);
        group.MapPut("/{id}", UpdateRole);
        group.MapDelete("/{id}", DeleteRole);

        return group;
    }

    private static async Task<IResult> CreateRole(HttpContext context, [FromBody] string name, [FromServices] RoleManager<IdentityRole> roleManager)
    {
        var role = new IdentityRole(name);
        await roleManager.CreateAsync(role);

        return Results.Created($"/roles/{role.Id}", role);
    }

    private static IResult GetAllRoles(HttpContext context, [FromServices] RoleManager<IdentityRole> roleManager)
    {
        var roles = roleManager.Roles.ToList();
        
        return Results.Ok(roles);
    }
    
    private static async Task<IResult> UpdateRole(HttpContext context, [FromRoute] string id, [FromBody] string name, [FromServices] RoleManager<IdentityRole> roleManager)
    {
        var role = await roleManager.FindByIdAsync(id);
        if (role is null)
        {
            return Results.NotFound();
        }

        role.Name = name;
        await roleManager.UpdateAsync(role);

        return Results.Ok(role);
    }
    
    private static async Task<IResult> DeleteRole(HttpContext context, [FromRoute] string id, [FromServices] RoleManager<IdentityRole> roleManager)
    {
        var role = await roleManager.FindByIdAsync(id);
        if (role is null)
        {
            return Results.NotFound();
        }

        await roleManager.DeleteAsync(role);

        return Results.NoContent();
    }
}

public record AddUserToRoleRequest(Guid UserId, string Role);