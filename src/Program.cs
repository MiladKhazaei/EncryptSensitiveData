using MyProject.AnonymizationService;

var builder = WebApplication.CreateBuilder(args);
// Run the application, copy the key from the console, then DELETE/COMMENT OUT this line
// Critical: Run this just in Local Environments, after Generate Key use it in Production Environment
string MyProjectAesKey = AnonymizationService.GenerateAesKey();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// ...