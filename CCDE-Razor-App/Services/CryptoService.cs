using System.Security.Cryptography;

namespace CCDE_Razor_App.Services;

/// <summary>
/// Service for encrypting and decrypting text using AES encryption with PBKDF2 key derivation.
/// </summary>
public class CryptoService : ICryptoService
{
    private const int OutputLength = 32; // 256 bits
    private const int MinSaltBytes = 16;
    private const int MinIterations = 100000;
    private const int MaxIterations = 5000000;
    private const int MinPasswordLength = 8;
    private const int IvLength = 16;

    private readonly string _password;
    private readonly byte[] _salt;
    private readonly int _iterations;
    private readonly ILogger<CryptoService>? _logger;

    /// <summary>
    /// Creates a new instance of CryptoService.
    /// </summary>
    /// <param name="password">The password/key for encryption.</param>
    /// <param name="saltBase64">The Base64-encoded salt.</param>
    /// <param name="iterations">The number of PBKDF2 iterations.</param>
    /// <param name="logger">Optional logger for logging errors.</param>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
    public CryptoService(string? password, string? saltBase64, int iterations, ILogger<CryptoService>? logger = null)
    {
        _logger = logger;

        // Validate and set password
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password/Key cannot be null or empty.", nameof(password));

        if (password.Length < MinPasswordLength)
            throw new ArgumentException($"Password/Key must be at least {MinPasswordLength} characters long.",
                nameof(password));

        _password = password;

        // Validate and set salt
        if (string.IsNullOrWhiteSpace(saltBase64))
            throw new ArgumentException("Salt cannot be null or empty.", nameof(saltBase64));

        try
        {
            _salt = Convert.FromBase64String(saltBase64);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Salt must be valid Base64.", nameof(saltBase64), ex);
        }

        if (_salt.Length < MinSaltBytes)
            throw new ArgumentException($"Salt must be at least {MinSaltBytes} bytes.", nameof(saltBase64));

        switch (iterations)
        {
            // Validate and set iterations
            case <= 0:
                throw new ArgumentException("Iterations must be a positive number.", nameof(iterations));
            case < MinIterations:
                _logger?.LogWarning("Iterations value {Iterations} below recommended minimum {MinIterations}", iterations,
                    MinIterations);
                break;
            case > MaxIterations:
                throw new ArgumentException($"Iterations must not exceed {MaxIterations}.", nameof(iterations));
        }

        _iterations = iterations;
    }

    /// <summary>
    /// Encrypts the given plain text using AES encryption with a randomly generated IV.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <returns>A CryptoResult containing the encrypted text or error message.</returns>
    public CryptoResult Encrypt(string plainText)
    {
        if (string.IsNullOrWhiteSpace(plainText))
            return new CryptoResult(false, null, "Plain text cannot be null or empty.");

        try
        {
            using var aesAlg = Aes.Create();
            var pbkdf2Key = Rfc2898DeriveBytes.Pbkdf2(
                _password,
                _salt,
                _iterations,
                HashAlgorithmName.SHA512,
                OutputLength);

            aesAlg.Key = pbkdf2Key;
            aesAlg.GenerateIV();
            var iv = aesAlg.IV;

            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using var msEncrypt = new MemoryStream();
            msEncrypt.Write(iv, 0, iv.Length);
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(plainText);
            }

            var encryptedBytes = msEncrypt.ToArray();
            var encryptedText = Convert.ToBase64String(encryptedBytes);

            return new CryptoResult(true, encryptedText, null);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Encryption failed");
            return new CryptoResult(false, null, "Encryption failed.");
        }
    }

    /// <summary>
    /// Decrypts the given encrypted text using AES decryption with IV extracted from the encrypted data.
    /// </summary>
    /// <param name="encryptedText">The Base64-encoded encrypted text (with IV prepended).</param>
    /// <returns>A CryptoResult containing the decrypted text or error message.</returns>
    public CryptoResult Decrypt(string encryptedText)
    {
        if (string.IsNullOrWhiteSpace(encryptedText))
            return new CryptoResult(false, null, "Encrypted text cannot be null or empty.");

        byte[] encryptedBytes;
        try
        {
            encryptedBytes = Convert.FromBase64String(encryptedText);
        }
        catch (FormatException ex)
        {
            _logger?.LogError(ex, "Invalid Base64 for encrypted text");
            return new CryptoResult(false, null, "Encrypted text is not valid Base64.");
        }

        if (encryptedBytes.Length < IvLength)
        {
            _logger?.LogError("Encrypted data length {Length} is less than IV length {IvLength}",
                encryptedBytes.Length, IvLength);
            return new CryptoResult(false, null, "Encrypted data is too short to contain an IV.");
        }

        var iv = new byte[IvLength];
        Array.Copy(encryptedBytes, 0, iv, 0, IvLength);

        var cipherText = new byte[encryptedBytes.Length - IvLength];
        Array.Copy(encryptedBytes, IvLength, cipherText, 0, cipherText.Length);

        try
        {
            using var aesAlg = Aes.Create();
            var pbkdf2Key = Rfc2898DeriveBytes.Pbkdf2(
                _password,
                _salt,
                _iterations,
                HashAlgorithmName.SHA512,
                OutputLength);

            aesAlg.Key = pbkdf2Key;
            aesAlg.IV = iv;

            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using var msDecrypt = new MemoryStream(cipherText);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            var decryptedText = srDecrypt.ReadToEnd();

            return new CryptoResult(true, decryptedText, null);
        }
        catch (CryptographicException ex)
        {
            _logger?.LogError(ex, "Decryption failed");
            return new CryptoResult(false, null,
                "Decryption failed. The encrypted text may be corrupted or use a different key.");
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Unexpected error during decryption");
            return new CryptoResult(false, null, "An unexpected error occurred during decryption.");
        }
    }
}