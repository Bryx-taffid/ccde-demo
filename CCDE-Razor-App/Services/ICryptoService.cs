namespace CCDE_Razor_App.Services;

public interface ICryptoService
{
    CryptoResult Encrypt(string plainText);
    CryptoResult Decrypt(string encryptedText);
}