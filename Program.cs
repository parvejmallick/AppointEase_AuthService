using System.Text;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = false;
    })
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

var jwtKey = builder.Configuration["Jwt:Key"]
    ?? throw new InvalidOperationException("Jwt:Key is missing from configuration.");

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddScoped<JwtTokenService>();
builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var database = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    database.Database.EnsureCreated();
    database.Database.ExecuteSqlRaw("ALTER TABLE \"AspNetUsers\" ADD COLUMN IF NOT EXISTS \"FirstName\" text NOT NULL DEFAULT '';");
    database.Database.ExecuteSqlRaw("ALTER TABLE \"AspNetUsers\" ADD COLUMN IF NOT EXISTS \"LastName\" text NOT NULL DEFAULT '';");
    database.Database.ExecuteSqlRaw("ALTER TABLE \"AspNetUsers\" ADD COLUMN IF NOT EXISTS \"DateOfBirth\" date NOT NULL DEFAULT DATE '0001-01-01';");
    database.Database.ExecuteSqlRaw("ALTER TABLE \"AspNetUsers\" ADD COLUMN IF NOT EXISTS \"Address\" text NOT NULL DEFAULT '';");
}

app.MapGet("/health", () => Results.Ok(new { status = "ok - Auth Service" }));
app.MapOpenApi();
app.MapScalarApiReference();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

