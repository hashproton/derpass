using System.Text.Json.Serialization;

namespace Api.Utils;

[JsonSerializable(typeof(TokenResponses))]
internal class TokenResponses
{
    public string AccessToken { get; set; } = default!;
    
    public string RefreshToken { get; set; } = default!;
}

[JsonSerializable(typeof(TokenResponses))]
internal sealed partial class TokenResponsesJsonSerializerContext : JsonSerializerContext
{
}