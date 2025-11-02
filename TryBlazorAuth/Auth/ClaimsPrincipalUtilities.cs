using System.Security.Claims;

namespace TryBlazorAuth.Auth;

public static class ClaimsPrincipalUtilities
{
    public static string? GetDisplayName(this ClaimsPrincipal principal) =>
        principal.GetClaimValue(ClaimTypes.Name);

    public static string? GetUserId(this ClaimsPrincipal principal) =>
        principal.GetClaimValue(ClaimTypes.NameIdentifier);

    public static string? GetEmail(this ClaimsPrincipal principal) =>
        principal.GetClaimValue(ClaimTypes.Email);

    public static string? GetRole(this ClaimsPrincipal principal) =>
        principal.GetClaimValue(ClaimTypes.Role);

    public static IEnumerable<string> GetRoles(this ClaimsPrincipal principal) =>
        principal.GetClaimValues(ClaimTypes.Role);

    private static string? GetClaimValue(this ClaimsPrincipal principal, string claimType) =>
        principal.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;

    private static IEnumerable<string> GetClaimValues(
        this ClaimsPrincipal principal,
        string claimType
    ) => principal.Claims.Where(c => c.Type == claimType).Select(c => c.Value);
}
