using CCDE_Razor_App.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace CCDE_Razor_App.Pages;

/// <summary>
/// The Index page model for encrypting and decrypting input text.
/// </summary>
public class IndexModel : PageModel
{
    private readonly ICryptoService _cryptoService;

    /// <summary>
    /// Constructor for dependency injection (allows injecting ICryptoService for testing).
    /// </summary>
    public IndexModel(ICryptoService cryptoService)
    {
        _cryptoService = cryptoService;
    }

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
    /// This error message is visible to the user in the UI.
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Handles the POST request where the input text is encrypted.
    /// </summary>
    public void OnPostEncrypt()
    {
        if (string.IsNullOrWhiteSpace(InputText))
        {
            ErrorMessage = "Input text must not be empty.";
            return;
        }

        var result = _cryptoService.Encrypt(InputText);
        if (result.Success)
        {
            EncryptedText = result.Value;
        }
        else
        {
            ErrorMessage = result.ErrorMessage;
        }
    }

    /// <summary>
    /// Handles the POST request for decryption where the encrypted text is decrypted.
    /// </summary>
    public void OnPostDecrypt()
    {
        if (string.IsNullOrWhiteSpace(EncryptedInputText))
        {
            ErrorMessage = "Encrypted text must not be empty.";
            return;
        }

        var result = _cryptoService.Decrypt(EncryptedInputText);
        if (result.Success)
        {
            DecryptedText = result.Value;
        }
        else
        {
            ErrorMessage = result.ErrorMessage;
        }
    }
}