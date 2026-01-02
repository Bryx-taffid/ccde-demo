using CCDE_Razor_App.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace CCDE_Razor_App.Tests;

public class CryptoServiceTests
{
    private const string TestPassword = "TestPassword123!";
    private const string TestSaltBase64 = "MTIzNDU2Nzg5MDEyMzQ1Ng=="; // 16 bytes
    private const int TestIterations = 100000;

    private static CryptoService CreateCryptoService()
    {
        return new CryptoService(TestPassword, TestSaltBase64, TestIterations);
    }

    [Fact]
    public void EncryptThenDecrypt_SimpleText_ReturnsOriginalText()
    {
        // Arrange
        var cryptoService = CreateCryptoService();
        const string originalText = "Hello World";

        // Act
        var encryptResult = cryptoService.Encrypt(originalText);
        var decryptResult = cryptoService.Decrypt(encryptResult.Value!);

        // Assert
        Assert.True(encryptResult.Success);
        Assert.NotNull(encryptResult.Value);
        Assert.Null(encryptResult.ErrorMessage);

        Assert.True(decryptResult.Success);
        Assert.Equal(originalText, decryptResult.Value);
        Assert.Null(decryptResult.ErrorMessage);
    }

    [Fact]
    public void EncryptThenDecrypt_TextWithSpecialCharacters_ReturnsOriginalText()
    {
        // Arrange
        var cryptoService = CreateCryptoService();
        const string originalText = "Test!@#$%^&*()_+{}[]|:;<>?,./äöüÄÖÜß€";

        // Act
        var encryptResult = cryptoService.Encrypt(originalText);
        var decryptResult = cryptoService.Decrypt(encryptResult.Value!);

        // Assert
        Assert.True(encryptResult.Success);
        Assert.True(decryptResult.Success);
        Assert.Equal(originalText, decryptResult.Value);
    }

    [Fact]
    public void EncryptThenDecrypt_LongText_ReturnsOriginalText()
    {
        // Arrange
        var cryptoService = CreateCryptoService();
        const string originalText = "This is a much longer text that contains multiple sentences. " +
                                    "It should test whether the encryption and decryption process " +
                                    "works correctly with larger amounts of data. " +
                                    "The text includes various punctuation marks and numbers like 123, 456, 789. " +
                                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        // Act
        var encryptResult = cryptoService.Encrypt(originalText);
        var decryptResult = cryptoService.Decrypt(encryptResult.Value!);

        // Assert
        Assert.True(encryptResult.Success);
        Assert.True(decryptResult.Success);
        Assert.Equal(originalText, decryptResult.Value);
    }

    [Theory]
    [InlineData("A")]
    [InlineData("Short")]
    [InlineData("Medium length text")]
    [InlineData("   Spaces at start and end   ")]
    public void EncryptThenDecrypt_VariousTextLengths_ReturnsOriginalText(string originalText)
    {
        // Arrange
        var cryptoService = CreateCryptoService();

        // Act
        var encryptResult = cryptoService.Encrypt(originalText);
        var decryptResult = cryptoService.Decrypt(encryptResult.Value!);

        // Assert
        Assert.True(encryptResult.Success);
        Assert.True(decryptResult.Success);
        Assert.Equal(originalText, decryptResult.Value);
    }

    [Fact]
    public void Encrypt_SameTextTwice_ProducesDifferentEncryptedResults()
    {
        // Arrange
        var cryptoService = CreateCryptoService();
        const string originalText = "Test";

        // Act
        var encryptResult1 = cryptoService.Encrypt(originalText);
        var encryptResult2 = cryptoService.Encrypt(originalText);

        // Assert
        Assert.True(encryptResult1.Success);
        Assert.True(encryptResult2.Success);
        Assert.NotEqual(encryptResult1.Value, encryptResult2.Value);
    }

    [Fact]
    public void Encrypt_EmptyString_ReturnsFailure()
    {
        // Arrange
        var cryptoService = CreateCryptoService();

        // Act
        var result = cryptoService.Encrypt(string.Empty);

        // Assert
        Assert.False(result.Success);
        Assert.Null(result.Value);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains("cannot be null or empty", result.ErrorMessage);
    }

    [Fact]
    public void Encrypt_NullString_ReturnsFailure()
    {
        // Arrange
        var cryptoService = CreateCryptoService();

        // Act
        var result = cryptoService.Encrypt(null!);

        // Assert
        Assert.False(result.Success);
        Assert.Null(result.Value);
        Assert.NotNull(result.ErrorMessage);
    }

    [Fact]
    public void Decrypt_EmptyString_ReturnsFailure()
    {
        // Arrange
        var cryptoService = CreateCryptoService();

        // Act
        var result = cryptoService.Decrypt(string.Empty);

        // Assert
        Assert.False(result.Success);
        Assert.Null(result.Value);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains("cannot be null or empty", result.ErrorMessage);
    }

    [Fact]
    public void Decrypt_InvalidBase64_ReturnsFailure()
    {
        // Arrange
        var cryptoService = CreateCryptoService();

        // Act
        var result = cryptoService.Decrypt("Invalid-Base64!");

        // Assert
        Assert.False(result.Success);
        Assert.Null(result.Value);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains("not valid Base64", result.ErrorMessage);
    }

    [Fact]
    public void Decrypt_TooShortData_ReturnsFailure()
    {
        // Arrange
        var cryptoService = CreateCryptoService();
        var tooShortData = Convert.ToBase64String(new byte[8]); // Less than IV length (16)

        // Act
        var result = cryptoService.Decrypt(tooShortData);

        // Assert
        Assert.False(result.Success);
        Assert.Null(result.Value);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains("too short", result.ErrorMessage);
    }

    [Fact]
    public void Decrypt_EncryptedWithDifferentKey_ReturnsFailure()
    {
        // Arrange
        var cryptoService1 = CreateCryptoService();
        var cryptoService2 = new CryptoService("DifferentPassword!", TestSaltBase64, TestIterations);
        const string originalText = "Secret Message";

        // Act
        var encryptResult = cryptoService1.Encrypt(originalText);
        var decryptResult = cryptoService2.Decrypt(encryptResult.Value!);

        // Assert
        Assert.True(encryptResult.Success);
        Assert.False(decryptResult.Success);
        Assert.NotNull(decryptResult.ErrorMessage);
        Assert.Contains("Decryption failed", decryptResult.ErrorMessage);
    }

    [Fact]
    public void Constructor_NullPassword_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new CryptoService(null!, TestSaltBase64, TestIterations));
        Assert.Contains("Password", exception.Message);
    }

    [Fact]
    public void Constructor_EmptyPassword_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new CryptoService(string.Empty, TestSaltBase64, TestIterations));
        Assert.Contains("Password", exception.Message);
    }

    [Fact]
    public void Constructor_TooShortPassword_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new CryptoService("short", TestSaltBase64, TestIterations));
        Assert.Contains("at least 8 characters", exception.Message);
    }

    [Fact]
    public void Constructor_NullSalt_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new CryptoService(TestPassword, null!, TestIterations));
        Assert.Contains("Salt", exception.Message);
    }

    [Fact]
    public void Constructor_InvalidBase64Salt_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new CryptoService(TestPassword, "Invalid-Base64!", TestIterations));
        Assert.Contains("valid Base64", exception.Message);
    }

    [Fact]
    public void Constructor_TooShortSalt_ThrowsArgumentException()
    {
        // Arrange
        var shortSalt = Convert.ToBase64String(new byte[8]); // Less than 16 bytes

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new CryptoService(TestPassword, shortSalt, TestIterations));
        Assert.Contains("at least 16 bytes", exception.Message);
    }

    [Fact]
    public void Constructor_ZeroIterations_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new CryptoService(TestPassword, TestSaltBase64, 0));
        Assert.Contains("positive number", exception.Message);
    }

    [Fact]
    public void Constructor_NegativeIterations_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new CryptoService(TestPassword, TestSaltBase64, -1000));
        Assert.Contains("positive number", exception.Message);
    }

    [Fact]
    public void Constructor_TooManyIterations_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new CryptoService(TestPassword, TestSaltBase64, 6000000));
        Assert.Contains("must not exceed", exception.Message);
    }

    [Fact]
    public void Constructor_LowIterations_LogsWarning()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CryptoService>>();

        // Act
        _ = new CryptoService(TestPassword, TestSaltBase64, 50000, mockLogger.Object);

        // Assert
        mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("below recommended minimum")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void EncryptThenDecrypt_MultilineText_ReturnsOriginalText()
    {
        // Arrange
        var cryptoService = CreateCryptoService();
        const string originalText = "Line 1\nLine 2\nLine 3\r\nLine 4";

        // Act
        var encryptResult = cryptoService.Encrypt(originalText);
        var decryptResult = cryptoService.Decrypt(encryptResult.Value!);

        // Assert
        Assert.True(encryptResult.Success);
        Assert.True(decryptResult.Success);
        Assert.Equal(originalText, decryptResult.Value);
    }
}