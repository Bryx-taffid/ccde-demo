using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CCDE_Razor_App.Pages;

/// <summary>
/// The Index page model for encrypting input text.
/// </summary>
/// <param name="logger">The logger to use.</param>
public class IndexModel(ILogger<IndexModel> logger) : PageModel
{
    private const int OutputLength = 32; // 256 bits
    private const int MinSaltBytes = 16;
    private const int MinIterations = 100000;
    private const int MaxIterations = 5000000;
    private const int MinPasswordLength = 8;
    private const int IvLength = 16;


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
    /// The encrypted text input for decryption.
    /// </summary>
    [BindProperty]
    public string? EncryptedInputText { get; set; }

    /// <summary>
    /// The decrypted text result.
    /// </summary>
    public string? DecryptedText { get; set; }

    /// <summary>
    /// This error message is visible to the user in the UI
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Handles the POST request, where the input text is encrypted.
    /// </summary>
    public void OnPostEncrypt()
    {
        if (string.IsNullOrWhiteSpace(InputText))
        {
            ErrorMessage = "Input text must not be empty.";
            return;
        }

        EncryptedText = Encrypt(InputText);
    }

    /// <summary>
    /// Handles the POST request for decryption, where the encrypted text is decrypted.
    /// </summary>
    public void OnPostDecrypt()
    {
        if (string.IsNullOrWhiteSpace(EncryptedInputText))
        {
            ErrorMessage = "Encrypted text must not be empty.";
            return;
        }

        DecryptedText = Decrypt(EncryptedInputText);
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

    /// <summary>
    /// Decrypts the given encrypted text using AES decryption with IV extracted from the encrypted data and a key derived from PBKDF2.
    /// </summary>
    /// <param name="encryptedText">The Base64-encoded encrypted text (with IV prepended).</param>
    /// <returns>The decrypted plain text.</returns>
    private string Decrypt(string encryptedText)
    {
        var password = SecretHelper.Key;
        var saltBase64 = SecretHelper.Salt;
        var iterations = SecretHelper.Iterations;

        // Validate password/key
        if (string.IsNullOrWhiteSpace(password))
        {
            ErrorMessage = "Decryption key is not configured.";
            logger.LogError("Crypto:Key is missing or empty");
            return string.Empty;
        }

        if (password.Length < MinPasswordLength)
        {
            ErrorMessage = "Decryption key is too short.";
            logger.LogError("Crypto:Key too short, must be at least {MinPasswordLength} characters long.",
                MinPasswordLength);
            return string.Empty;
        }

        // Validate salt (present, Base64, length)
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

        // Validate iterations (positive, within range)
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

        // Decode Base64 encrypted data
        byte[] encryptedBytes;
        try
        {
            encryptedBytes = Convert.FromBase64String(encryptedText);
        }
        catch (FormatException ex)
        {
            ErrorMessage = "Encrypted text is not valid Base64.";
            logger.LogError(ex, "Invalid Base64 for encrypted text");
            return string.Empty;
        }

        // Validate minimum length (must contain at least IV)
        if (encryptedBytes.Length < IvLength)
        {
            ErrorMessage = "Encrypted data is too short to contain an IV.";
            logger.LogError("Encrypted data length {Length} is less than IV length {IvLength}", encryptedBytes.Length,
                IvLength);
            return string.Empty;
        }

        // Extract IV from the first 16 bytes
        var iv = new byte[IvLength];
        Array.Copy(encryptedBytes, 0, iv, 0, IvLength);

        // Extract ciphertext (everything after IV)
        var cipherText = new byte[encryptedBytes.Length - IvLength];
        Array.Copy(encryptedBytes, IvLength, cipherText, 0, cipherText.Length);

        // Derive key using same parameters as encryption
        using var aesAlg = Aes.Create();
        var pbkdf2Key = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA512,
            OutputLength);

        aesAlg.Key = pbkdf2Key;
        aesAlg.IV = iv;

        // Decrypt
        var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        try
        {
            using var msDecrypt = new MemoryStream(cipherText);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            return srDecrypt.ReadToEnd();
        }
        catch (CryptographicException ex)
        {
            ErrorMessage = "Decryption failed. The encrypted text may be corrupted or use a different key.";
            logger.LogError(ex, "Decryption failed");
            return string.Empty;
        }
    }
}