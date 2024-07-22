namespace Api;

internal static partial class LoggingExtensions
{
    [LoggerMessage(10, LogLevel.Information, "AuthenticationScheme: {AuthenticationScheme} signed in.", EventName = "AuthenticationSchemeSignedIn")]
    public static partial void AuthenticationSchemeSignedIn(this ILogger logger, string authenticationScheme);

    [LoggerMessage(11, LogLevel.Information, "AuthenticationScheme: {AuthenticationScheme} signed out.", EventName = "AuthenticationSchemeSignedOut")]
    public static partial void AuthenticationSchemeSignedOut(this ILogger logger, string authenticationScheme);
}