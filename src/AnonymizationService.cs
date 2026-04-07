using System.Text;
using System.Security.Cryptography;

public class AnonymizationService
{
    // In production, inject this via Key Vault or secure configuration like IConfiguration
    private readonly byte[] _hmacKey = Encoding.UTF8.GetBytes("Secret_Server_Side_Key_Here");
    // 32-byte key for AES-256. Inject securely in production!
    private readonly byte[] _aesKey = Encoding.UTF8.GetBytes("12345678901234567890123456789012_Inject_in_Production");

    // Deterministic Hashing for Searchable exact-matches (Such as NationalId)
    public string? HashData(string? rawData)
    {
        if (string.IsNullOrWhiteSpace(rawData)) return null;

        // 1. Create HMAC instance with the secret key
        using var hmac = new HMACSHA256(_hmacKey);

        // 2. Normalize input (uppercase/trim) to ensure consistent DB queries
        byte[] inputBytes = Encoding.UTF8.GetBytes(rawData.Trim().ToUpperInvariant());
        byte[] hashBytes = hmac.ComputeHash(inputBytes);

        // 3. Return as Hex string for easy database storage
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    // Encrypt
    public string? EncryptData(string? rawData)
    {
        if (string.IsNullOrWhiteSpace(rawData)) return null;

        byte[] plainBytes = Encoding.UTF8.GetBytes(rawData);

        // Generate a CRITICAL Random Nonce (IV) for every single encryption
        byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);

        byte[] cipherBytes = new byte[plainBytes.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

        // Encrypt and generate Authentication Tag
        using var aesGcm = new AesGcm(_aesKey, AesGcm.TagByteSizes.MaxSize);
        aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

        // Pack Nonce + Tag + Ciphertext into one array for storage
        byte[] payload = new byte[nonce.Length + tag.Length + cipherBytes.Length];
        Buffer.BlockCopy(nonce, 0, payload, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, payload, nonce.Length, tag.Length);
        Buffer.BlockCopy(cipherBytes, 0, payload, nonce.Length + tag.Length, cipherBytes.Length);

        return Convert.ToBase64String(payload);
    }

    // Decrypt
    public string? DecryptData(string? encryptedData)
    {
        if (string.IsNullOrWhiteSpace(encryptedData)) return null;

        byte[] payload = Convert.FromBase64String(encryptedData);

        int nonceSize = AesGcm.NonceByteSizes.MaxSize;
        int tagSize = AesGcm.TagByteSizes.MaxSize;
        int cipherSize = payload.Length - nonceSize - tagSize;

        // Extract the components from the database string
        byte[] nonce = new byte[nonceSize];
        byte[] tag = new byte[tagSize];
        byte[] cipherBytes = new byte[cipherSize];

        Buffer.BlockCopy(payload, 0, nonce, 0, nonceSize);
        Buffer.BlockCopy(payload, nonceSize, tag, 0, tagSize);
        Buffer.BlockCopy(payload, nonceSize + tagSize, cipherBytes, 0, cipherSize);

        byte[] plainBytes = new byte[cipherSize];

        // Decrypt. 
        // This will automatically throw an exception if data was tampered with
        using var aesGcm = new AesGcm(_aesKey, tagSize);
        aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    // Extra Developer Utility  for Generate Key for AES securely
    public static string GenerateAesKey()
    {
        byte[] key = new byte[32];
        // Using OS RandomNumberGenerator()
        using (var rng = RandomNumberGenerator.Create())
        {
            // Generate key
            rng.GetBytes(key);
        }
        Console.WriteLine($"AES Secure Key: {Convert.ToBase64String(key)}");
        return Convert.ToBase64String(key);
    }
}