using Api;
using Api.Endpoints;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddDbContext<ApplicationDbContext>(op => op.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")))
    .AddIdentityDerpassServices()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services
    .AddAuthorization()
    .AddEndpointsApiExplorer()
    .AddSwaggerGen();

var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger()
        .UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGroup("/roles")
    .WithTags("Roles")
    .RequireAuthorization(b => b.RequireRole("admin"))
    .MapRolesApi();

app.MapGroup("/users")
    .WithTags("Manage Users")
    .RequireAuthorization(b => b.RequireRole("admin"))
    .MapUsersApi();

app.MapGroup("/new-identity")
    .MapIdentityApi()
    .WithTags("New Identity");

app
    .MapGroup("/identity")
    .MapIdentityApi<User>()
    .WithTags("Identity");

app.UseAuthentication()
    .UseAuthorization();

app.Run();