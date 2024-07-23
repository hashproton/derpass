using Api.Configuration;
using Api.Configuration.Options;
using Api.Entities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Api;

public static class DerpassIdentity
{
    public static IdentityBuilder AddIdentityDerpassServices(this IServiceCollection services) =>
        services.AddIdentityDerpassServices(_ =>
        {
        });

    public static IdentityBuilder AddIdentityDerpassServices(
        this IServiceCollection services,
        Action<IdentityOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddJwtOptions();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme);
        
        return services.AddIdentityCore<User>(configure)
            .AddApiEndpoints();
    }
    
    private static IServiceCollection AddJwtOptions(this IServiceCollection services)
    {
        services.AddOptions<JwtOptions>()
            .BindConfiguration(nameof(JwtOptions))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddSingleton<IConfigureOptions<JwtBearerOptions>, ConfigureJwtBearerOptions>();
        
        return services;
    }
}