#if DEBUG
using System.Text;
#endif
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
        throw new Exception("KeyVault URL is missing");
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
    var result = int.TryParse(builder.Configuration[iterationName], out var iterations);
    ValidateIntConversion(result, iterations);
}
// TODO: get the secret for development from .NET user secrets


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
        throw new Exception("Iterations not found");
}

string GetSecret(SecretTypes secret)
{
    string secretName;
    switch (secret)
    {
        case SecretTypes.Key:
            secretName = "Key";
            break;
        case SecretTypes.Salt:
            secretName = "Salt";
            break;
        case SecretTypes.Iterations:
            secretName = "Iterations";
            break;
        default:
            return "";
    }

#if DEBUG
    var sb = new StringBuilder("Crypto:");
    sb.Append(secretName);
    var resultName = sb.ToString();
#else
    var resultName = secretName;
#endif
    return resultName;
}

// BUG: CSS for the Web App is missing in Azure / production version