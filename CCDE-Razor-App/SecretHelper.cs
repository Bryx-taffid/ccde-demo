namespace CCDE_Razor_App;

/// <summary>
/// Saves the secrets from Azure DevOps or .NET secrets
/// </summary>
internal static class SecretHelper
{
    // Note: Uses lock to ensure thread-safety for static properties
    // This is done based on the recommendations from the code review
    private static readonly Lock SyncRoot = new();

    internal static string? Key
    {
        get
        {
            lock (SyncRoot)
            {
                return field;
            }
        }
        set
        {
            lock (SyncRoot)
            {
                field = value;
            }
        }
    }

    internal static string? Salt
    {
        get
        {
            lock (SyncRoot)
            {
                return field;
            }
        }
        set
        {
            lock (SyncRoot)
            {
                field = value;
            }
        }
    }

    internal static int Iterations
    {
        get
        {
            lock (SyncRoot)
            {
                return field;
            }
        }
        set
        {
            lock (SyncRoot)
            {
                field = value;
            }
        }
    }
}