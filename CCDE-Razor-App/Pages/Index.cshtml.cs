using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CCDE_Razor_App.Pages;

public class IndexModel(IConfiguration config) : PageModel
{
    // TODO: Apply the best practices and recommendations regarding accessibility

    private const int OutputLength = 32; // 256 bits

    /// <summary>
    /// The input text to be encrypted.
    /// </summary>
    [BindProperty]
    public string? InputText { get; set; }

    /// <summary>
    /// The encrypted text result.
    /// </summary>
    public string? EncryptedText { get; set; }

    /// <summary>
    /// Handles the POST request, where the input text is encrypted.
    /// </summary>
    public void OnPost()
    {
        if (!string.IsNullOrEmpty(InputText))
        {
            EncryptedText = Encrypt(InputText);
        }
    }

    // BUG: No IV, so decryption is impossible.

    /// <summary>
    /// Encrypts the given plain text using AES encryption with a key derived from PBKDF2.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <returns>The encrypted text.</returns>
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