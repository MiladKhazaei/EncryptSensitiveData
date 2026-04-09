using Microsoft.EntityFrameworkCore;

public class HealthcareDbContext : DbContext
{
    private readonly AnonymizationService _anonymizationService;

    // Inject the AnonymizationService directly into your DbContext
    public HealthcareDbContext(
        DbContextOptions<HealthcareDbContext> options,
        AnonymizationService anonymizationService) : base(options)
    {
        _anonymizationService = anonymizationService;
    }

    public DbSet<PatientInformationEntity> Patients { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Instantiate our custom converters
        var aesConverter = new AesGcmStringConverter(_anonymizationService);
        var hmacConverter = new HmacStringConverter(_anonymizationService);

        // Apply Converters to specific entity properties
        modelBuilder.Entity<PatientInformationEntity>(entity =>
        {
            // Apply Hashing to National ID
            entity.Property(e => e.NationalId)
                  .HasConversion(hmacConverter)
                  .HasMaxLength(64); // Hashes are fixed length

            // Apply Encryption to Phone
            entity.Property(e => e.Phone)
                  .HasConversion(aesConverter)
                  .HasMaxLength(256); // Ciphertext + Nonce + Tag + Base64 expansion
        });
    }
}using Microsoft.EntityFrameworkCore;

public class HealthcareDbContext : DbContext
{
    private readonly AnonymizationService _anonymizationService;

    // Inject the AnonymizationService directly into your DbContext
    public HealthcareDbContext(
        DbContextOptions<HealthcareDbContext> options,
        AnonymizationService anonymizationService) : base(options)
    {
        _anonymizationService = anonymizationService;
    }

    public DbSet<PatientInformationEntity> Patients { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Instantiate our custom converters
        var aesConverter = new AesGcmStringConverter(_anonymizationService);
        var hmacConverter = new HmacStringConverter(_anonymizationService);

        // Apply Converters to specific entity properties
        modelBuilder.Entity<PatientInformationEntity>(entity =>
        {
            // Apply Hashing to National ID
            entity.Property(e => e.NationalId)
                  .HasConversion(hmacConverter)
                  .HasMaxLength(64); // Hashes are fixed length

            // Apply Encryption to Phone
            entity.Property(e => e.Phone)
                  .HasConversion(aesConverter)
                  .HasMaxLength(256); // Ciphertext + Nonce + Tag + Base64 expansion
        });
    }
}