using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CCDE_Razor_App.Pages;

public class IndexModel : PageModel
{
    private static readonly byte[] EncryptionKey =
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
    ];

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

    private static string Encrypt(string plainText)
    {
        using var aesAlg = Aes.Create();
        aesAlg.Key = EncryptionKey;

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