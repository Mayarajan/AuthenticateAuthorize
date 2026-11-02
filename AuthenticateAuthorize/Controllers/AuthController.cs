using System.IdentityModel.Tokens.Jwt; // For legacy handler, or use JsonWebTokenHandler
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace YourProject.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // 1. HARDCODED CHECK FOR TESTING (Replace with database validation later)
        if (request.Username == "admin" && request.Password == "password123")
        {
            // 2. Pull settings from appsettings.json
            var jwtKey = _configuration["JwtSettings:Key"]!;
            var jwtIssuer = _configuration["JwtSettings:Issuer"];
            var jwtAudience = _configuration["JwtSettings:Audience"];

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // 3. Define the user's claims (Identity data)
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, request.Username),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // 5. Return the token string to the client
            return Ok(new { Token = CreateJwt(claims) });
        }

        return Unauthorized("Invalid credentials. Try username: admin, password: password123");
    }

    // Step 1: send the browser to Google
    [HttpGet("google-login")]
    public IActionResult GoogleLogin()
    {
        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(GoogleCallback))
        };
        return Challenge(props, "Google");
    }

    // Step 2: Google sent the user back; trade Google's identity for YOUR JWT
    [HttpGet("signin-google")]
    public async Task<IActionResult> GoogleCallback()
    {
        var result = await HttpContext.AuthenticateAsync("External");
        if (!result.Succeeded || result.Principal is null)
            return Unauthorized("Google authentication failed.");

        var googleId = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
        var email = result.Principal.FindFirstValue(ClaimTypes.Email);
        var name = result.Principal.FindFirstValue(ClaimTypes.Name);

        // Throw away the temporary cookie, we don't need it anymore
        await HttpContext.SignOutAsync("External");

        if (googleId is null || email is null)
            return Unauthorized("Google did not return the expected claims.");

        // TODO: look up or create a local user by googleId/email in your database
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, googleId),
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Name, name ?? email),
            new Claim(ClaimTypes.Role, "User"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        return Ok(new { Token = CreateJwt(claims) });
    }


    private string CreateJwt(IEnumerable<Claim> claims)
    {
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration["JwtSettings:Key"]!));
        var minutes = int.Parse(_configuration["JwtSettings:ExpiryInMinutes"] ?? "60");

        var token = new JwtSecurityToken(
            issuer: _configuration["JwtSettings:Issuer"],
            audience: _configuration["JwtSettings:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(minutes),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

// Simple request model
public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
