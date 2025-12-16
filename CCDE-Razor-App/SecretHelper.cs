namespace CCDE_Razor_App;

/// <summary>
/// Saves the secrets from Azure DevOps or .NET secrets
/// </summary>
internal static class SecretHelper
{
    internal static string? Key { get; set; }
    internal static string? Salt { get; set; }
    internal static int Iterations { get; set; }
}