using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

public class AesGcmStringConverter : ValueConverter<string?, string?>
{
    public AesGcmStringConverter(AnonymizationService anonymizationService, ConverterMappingHints? mappingHints = null)
        : base(
            // Write to DB (convert C# string to encrypted Base64)
            modelValue => anonymizationService.EncryptData(modelValue),
            // Read from DB (convert Base64 back to plain C# string)
            providerValue => anonymizationService.DecryptData(providerValue),
            mappingHints)
    {
    }
}

public class HmacStringConverter : ValueConverter<string?, string?>
{
    public HmacStringConverter(AnonymizationService anonymizationService, ConverterMappingHints? mappingHints = null)
        : base(
            // Write to DB (convert C# string to Hash)
            modelValue => anonymizationService.HashData(modelValue),
            // Read from DB (cannot decrypt, so just return the hash to the C# model)
            providerValue => providerValue,
            mappingHints)
    {
    }
}