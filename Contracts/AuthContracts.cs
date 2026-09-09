namespace AuthService.Contracts;

public sealed record SignupRequest(
	string Email,
	string Password,
	string FirstName,
	string LastName,
	string PhoneNumber,
	DateOnly DateOfBirth,
	string Address);

public sealed record LoginRequest(string Email, string Password);

public sealed record UpdateUserRequest(
	string FirstName,
	string LastName,
	DateOnly DateOfBirth,
	string PhoneNumber,
	string Address);

public sealed record AuthResponse(string AccessToken, DateTime ExpiresAtUtc);

public sealed record UserResponse(
	string Id,
	string Email,
	string FirstName,
	string LastName,
	DateOnly DateOfBirth,
	string PhoneNumber,
	string Address);
