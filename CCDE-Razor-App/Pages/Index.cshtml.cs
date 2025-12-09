using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CCDE_Razor_App.Pages;

public class IndexModel(IConfiguration config, ILogger logger) : PageModel
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
    /// Encrypts the given plain text using AES encryption with a randomly generated IV (prepended to encrypted output) and a key derived from PBKDF2.
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
            logger.LogError("password, salt, or iterations in the secrets handling is missing");
            return "";
        }

        byte[] salt;
        int iterations;
        try
        {
            salt = Convert.FromBase64String(config["Crypto:Salt"]!);
        }
        catch (FormatException ex)
        {
            logger.LogError("Invalid Base64 for salt: {ExMessage}", ex.Message);
            return "";
        }
        catch (ArgumentException ex)
        {
            logger.LogError("Invalid argument for salt: {ExMessage}", ex.Message);
            return "";
        }

        try
        {
            iterations = int.Parse(config["Crypto:Iterations"]!);
        }
        catch (FormatException ex)
        {
            logger.LogError("Invalid number for iterations: {ExMessage}", ex.Message);
            return "";
        }
        catch (ArgumentException ex)
        {
            logger.LogError("Invalid argument for iterations: {ExMessage}", ex.Message);
            return "";
        }

        var pbkdf2Key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA512, OutputLength);

        aesAlg.Key = pbkdf2Key;

        // Generate random, secure 16-byte IV
        aesAlg.GenerateIV();
        var iv = aesAlg.IV;

        var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        using var msEncrypt = new MemoryStream();
        // Prepend IV to the ciphertext (IV is first 16 bytes)
        msEncrypt.Write(iv, 0, iv.Length);
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText); // write plaintext to CryptoStream
        }

        var encryptedBytes = msEncrypt.ToArray(); // IV + ciphertext
        return Convert.ToBase64String(encryptedBytes);
    }
}