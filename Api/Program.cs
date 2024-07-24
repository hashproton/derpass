using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Api;
using Api.Endpoints;
using Api.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddDbContext<ApplicationDbContext>(op => op.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")))
    // .AddIdentityApiEndpoints<User>()
    .AddIdentityDerpassServices()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services
    .AddAuthorization()
    .AddEndpointsApiExplorer()
    .AddSwaggerGen();

builder.Services
    .AddCors();

var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger()
        .UseSwaggerUI();

    app
        .UseCors(op =>
        {
            op.AllowAnyHeader()
                .AllowAnyMethod()
                .AllowAnyOrigin();
        });
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

// app
//     .MapGroup("/identity")
//     .MapIdentityApi<User>()
//     .WithTags("Identity");

app.UseAuthentication()
    .UseAuthorization();

app.Run();