using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using CCDE_Razor_App;

var environment =
#if DEBUG
    Environments.Development;
#else
    Environments.Production;
#endif

var keyName = GetSecret(SecretTypes.Key);
var saltName = GetSecret(SecretTypes.Salt);
var iterationName = GetSecret(SecretTypes.Iterations);

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    EnvironmentName = environment, // important: sets the correct environment (dev/prod) based on the run profile
    Args = args
});

if (builder.Environment.IsProduction())
{
    var keyVaultUrl = Environment.GetEnvironmentVariable("VAULT_URL");
    if (string.IsNullOrWhiteSpace(keyVaultUrl))
    {
        throw new Exception("Environment variable 'VAULT_URL' is not configured.");
    }

    var client = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());

    // get secrets (those are saved like key.value, salt.value,...)
    var key = await client.GetSecretAsync(keyName);
    var salt = await client.GetSecretAsync(saltName);
    var iterationSecret = await client.GetSecretAsync(iterationName);
    SecretHelper.Salt = salt.Value.Value;
    SecretHelper.Key = key.Value.Value;
    var result = int.TryParse(iterationSecret.Value.Value, out var iterations);
    ValidateIntConversion(result, iterations);
}

else
{
    // get the secrets from .NET secrets
    SecretHelper.Key = builder.Configuration[keyName];
    SecretHelper.Salt = builder.Configuration[saltName];
    if (string.IsNullOrWhiteSpace(SecretHelper.Key) || string.IsNullOrWhiteSpace(SecretHelper.Salt))
    {
        throw new Exception("Could not fetch secrets from .NET User secrets");
    }

    var result = int.TryParse(builder.Configuration[iterationName], out var iterations);
    ValidateIntConversion(result, iterations);
}


// Add services to the container.
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
    .WithStaticAssets();

app.Run();
return;

// Converts string to int (if possible)
void ValidateIntConversion(bool result, int iterations)
{
    if (result)
        SecretHelper.Iterations = iterations;
    else
        throw new Exception("Iterations must be a valid integer");
}

string GetSecret(SecretTypes secret)
{
    var secretName = secret switch
    {
        SecretTypes.Key => "Key",
        SecretTypes.Salt => "Salt",
        SecretTypes.Iterations => "Iterations",
        _ => throw new ArgumentOutOfRangeException(nameof(secret), secret, "This secret type is not supported.")
    };

#if DEBUG
    return $"Crypto:{secretName}";
#else
    return secretName;
#endif
}