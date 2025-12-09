using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CCDE_Razor_App.Pages;

public class IndexModel(IConfiguration config) : PageModel
{
    private const int OutputLength = 32;

    [BindProperty] public string? InputText { get; set; }

    public string? EncryptedText { get; set; }

    public void OnGet()
    {
    }

    public void OnPost()
    {
        if (!string.IsNullOrEmpty(InputText))
        {
            EncryptedText = Encrypt(InputText);
        }
    }

    private string Encrypt(string plainText)
    {
        using var aesAlg = Aes.Create();
        var password = config["Crypto:Key"];
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(config["Crypto:Salt"]) ||
            string.IsNullOrEmpty(config["Crypto:Iterations"]))
        {
            Console.WriteLine("password, salt, or iterations in the secrets handling is missing");
            return "";
        }

        var salt = Convert.FromBase64String(config["Crypto:Salt"]!);
        var iterations = int.Parse(config["Crypto:Iterations"]!);

        var pbkdf2Key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, OutputLength);

        aesAlg.Key = pbkdf2Key;

        var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        using var msEncrypt = new MemoryStream();
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        var encryptedBytes = msEncrypt.ToArray();
        return Convert.ToBase64String(encryptedBytes);
    }
}