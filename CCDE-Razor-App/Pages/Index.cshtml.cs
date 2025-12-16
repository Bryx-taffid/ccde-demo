using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CCDE_Razor_App.Pages;

/// <summary>
/// TODO: comment
/// </summary>
/// <param name="logger"></param>
public class IndexModel(ILogger<IndexModel> logger) : PageModel
{
    // TODO: Apply the best practices and recommendations regarding accessibility

    private const int OutputLength = 32; // 256 bits
    private const int MinSaltBytes = 16;
    private const int MinIterations = 100000;
    private const int MaxIterations = 5000000;
    private const int MinPasswordLength = 8;

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
    /// This error message is visible to the user in the UI
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Handles the POST request, where the input text is encrypted.
    /// </summary>
    public void OnPost()
    {
        if (string.IsNullOrWhiteSpace(InputText))
        {
            ErrorMessage = "Input text must not be empty.";
            return;
        }

        EncryptedText = Encrypt(InputText);
    }

    /// <summary>
    /// Encrypts the given plain text using AES encryption with a randomly generated IV (prepended to encrypted output) and a key derived from PBKDF2.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <returns>The encrypted text.</returns>
    private string Encrypt(string plainText)
    {
        var password = SecretHelper.Key;
        var saltBase64 = SecretHelper.Salt;
        var iterations = SecretHelper.Iterations;


        // 1) Validate password/key
        if (string.IsNullOrWhiteSpace(password))
        {
            ErrorMessage = "Encryption key is not configured.";
            logger.LogError("Crypto:Key is missing or empty");
            return string.Empty;
        }

        if (password.Length < MinPasswordLength)
        {
            ErrorMessage = "Encryption key is too short.";
            logger.LogError("Crypto:Key too short, must be at least {MinPasswordLength} characters long.",
                MinPasswordLength);
            return string.Empty;
        }

        // 2) Validate salt (present, Base64, length)
        if (string.IsNullOrWhiteSpace(saltBase64))
        {
            ErrorMessage = "Salt is not configured.";
            logger.LogError("Crypto:Salt is missing or empty");
            return string.Empty;
        }

        byte[] salt;
        try
        {
            salt = Convert.FromBase64String(saltBase64);
        }
        catch (FormatException ex)
        {
            ErrorMessage = "Salt must be possible to decode.";
            logger.LogError(ex, "Invalid Base64 for salt");
            return string.Empty;
        }

        if (salt.Length < MinSaltBytes)
        {
            ErrorMessage = $"Salt must be at least {MinSaltBytes} bytes.";
            logger.LogError("Salt length {Length} is below minimum {MinSaltBytes}", salt.Length, MinSaltBytes);
            return string.Empty;
        }

        // 3) Validate iterations (positive, within range)
        switch (iterations)
        {
            case <= 0:
                ErrorMessage = "Iteration count must be a positive number.";
                logger.LogError("Iterations value {Iterations} is not positive", iterations);
                return string.Empty;
            case < MinIterations:
                ErrorMessage = $"Iteration count must be at least {MinIterations}.";
                logger.LogWarning("Iterations value {Iterations} below recommended minimum {MinIterations}", iterations,
                    MinIterations);
                return string.Empty;
            case > MaxIterations:
                ErrorMessage = $"Iteration count must not exceed {MaxIterations}.";
                logger.LogWarning("Iterations value {Iterations} above maximum {MaxIterations}", iterations,
                    MaxIterations);
                return string.Empty;
        }

        // 4) Derive key and encrypt
        using var aesAlg = Aes.Create();
        var pbkdf2Key = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA512,
            OutputLength);

        aesAlg.Key = pbkdf2Key;

        // Generate random, secure 16-byte IV
        aesAlg.GenerateIV();
        var iv = aesAlg.IV;

        var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        using var msEncrypt = new MemoryStream();
        // Prepend IV to the ciphertext (IV is first 16 bytes)
        msEncrypt.Write(iv, 0, iv.Length);
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        var encryptedBytes = msEncrypt.ToArray();
        return Convert.ToBase64String(encryptedBytes);
    }
}