using AuthService.Contracts;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    JwtTokenService tokenService,
    ILogger<AuthController> logger) : ControllerBase
{
    [HttpPost("signup")]
    public async Task<ActionResult<AuthResponse>> Signup(SignupRequest request)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email.Trim(),
            Email = request.Email.Trim(),
            FirstName = request.FirstName.Trim(),
            LastName = request.LastName.Trim(),
            PhoneNumber = request.PhoneNumber.Trim(),
            DateOfBirth = request.DateOfBirth,
            Address = request.Address.Trim()
        };

        var result = await userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors.Select(error => error.Description) });
        }

        return Ok(await CreateAuthResponseAsync(user));
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Login(LoginRequest request)
    {
        var user = await userManager.FindByEmailAsync(request.Email.Trim());
        if (user is null)
        {
            logger.LogWarning("Login failed: no user found for email {Email}.", request.Email.Trim());
            return Unauthorized(new { error = "Invalid email or password." });
        }

        logger.LogInformation("User found for login: {UserId}.", user.Id);

        var passwordCheck = await signInManager.CheckPasswordSignInAsync(user, request.Password, true);
        if (!passwordCheck.Succeeded)
        {
            logger.LogWarning("Login failed: invalid password for user {UserId}.", user.Id);
            return Unauthorized(new { error = "Invalid email or password." });
        }

        logger.LogInformation("User authenticated successfully: {UserId}.", user.Id);
        return Ok(await CreateAuthResponseAsync(user));
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<ActionResult<UserResponse>> Me()
    {
        var user = await userManager.GetUserAsync(User);
        return user is null
            ? Unauthorized()
            : Ok(ToUserResponse(user));
    }

    [Authorize]
    [HttpPut("me")]
    public async Task<ActionResult<UserResponse>> UpdateMe(UpdateUserRequest request)
    {
        var user = await userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        user.FirstName = request.FirstName.Trim();
        user.LastName = request.LastName.Trim();
        user.DateOfBirth = request.DateOfBirth;
        user.PhoneNumber = request.PhoneNumber.Trim();
        user.Address = request.Address.Trim();

        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            return BadRequest(new { errors = result.Errors.Select(error => error.Description) });
        }

        return Ok(ToUserResponse(user));
    }

    private async Task<AuthResponse> CreateAuthResponseAsync(ApplicationUser user)
    {
        return tokenService.GenerateToken(user);
    }

    private static UserResponse ToUserResponse(ApplicationUser user)
    {
        return new UserResponse(
            user.Id,
            user.Email ?? string.Empty,
            user.FirstName,
            user.LastName,
            user.DateOfBirth,
            user.PhoneNumber ?? string.Empty,
            user.Address);
    }
}
