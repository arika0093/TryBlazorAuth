using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BitzArt.Blazor.Auth;
using BitzArt.Blazor.Auth.Server;
using Microsoft.IdentityModel.Tokens;

namespace TryBlazorAuth.Auth;

public class SampleAuthService : AuthenticationService<SignInPayload>
{
    // デモ用にInMemoryでユーザー情報とトークンを保持 ---
    // 実際にはDBなどに保存してください。
    private Dictionary<string, UserInfo> Users { get; } =
        new()
        {
            ["user1"] = new UserInfo("user1", "user1", "Alice", "User"),
            ["user2"] = new UserInfo("user2", "user2", "Bob", "User"),
            ["admin"] = new UserInfo("admin", "admin", "Charlie", "Admin"),
        };
    private Dictionary<string, string> UsersRefreshTokens { get; } = [];

    // ------------------------------------------
    // 有効期限の設定
    private readonly TimeSpan AccessTokenDuration = TimeSpan.FromMinutes(15); // 短く
    private readonly TimeSpan RefreshTokenDuration = TimeSpan.FromDays(30); // 長く

    // JWT生成のための設定
    private readonly SigningCredentials _signingCredentials;
    private readonly JwtSecurityTokenHandler _tokenHandler;

    public SampleAuthService()
    {
        // 32文字以上推奨。実際にはIConfigurationなどから取得してください。
        var secretKey = "SuperSecretKeyForJwtTokenGeneration12345";
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        _signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        _tokenHandler = new JwtSecurityTokenHandler();
    }

    public override async Task<AuthenticationResult> SignInAsync(
        SignInPayload signInPayload,
        CancellationToken cancellationToken = default
    )
    {
        // DB取得等を想定して少し遅延させる
        await Task.Delay(1000, cancellationToken);
        // ユーザーを拾ってきて、パスワードを検証する
        if (
            Users.TryGetValue(signInPayload.Id, out var user)
            && user.Password == signInPayload.Password
        )
        {
            return LoginSuccessful(user);
        }
        else
        {
            return Failure("Invalid credentials");
        }
    }

    public override async Task<AuthenticationResult> RefreshJwtPairAsync(
        string refreshToken,
        CancellationToken cancellationToken = default
    )
    {
        // dummy delay
        await Task.Delay(100, cancellationToken);
        // refresh tokenを検証する
        if (UsersRefreshTokens.Any(kvp => kvp.Value == refreshToken))
        {
            // User情報を取得して、新しいJWTペアを発行する
            var userId = UsersRefreshTokens.First(kvp => kvp.Value == refreshToken).Key;
            var user = Users[userId];
            return LoginSuccessful(user);
        }
        else
        {
            return Failure("Invalid refresh token");
        }
    }

    private AuthenticationResult LoginSuccessful(UserInfo user)
    {
        // ユーザー情報をclaimsに追加する
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, user.Name),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Role, user.Role),
        };
        var jwt = BuildJwtPair(claims);
        return Success(jwt);
    }

    private JwtPair BuildJwtPair(IEnumerable<Claim> claims)
    {
        var now = DateTime.UtcNow;

        // Access token
        // ユーザー権限(claims)をここで追加する。
        var accessTokenExpiresAt = now + AccessTokenDuration;
        var accessToken = _tokenHandler.WriteToken(
            new JwtSecurityToken(
                claims: claims,
                notBefore: now,
                expires: accessTokenExpiresAt,
                signingCredentials: _signingCredentials
            )
        );

        // Refresh token
        // JWTを更新するのに使用されるトークン
        var refreshTokenExpiresAt = now + RefreshTokenDuration;
        var refreshToken = _tokenHandler.WriteToken(
            new JwtSecurityToken(
                notBefore: now,
                expires: refreshTokenExpiresAt,
                signingCredentials: _signingCredentials
            )
        );

        return new JwtPair(accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt);
    }
}

// ログインに必要な情報
public class SignInPayload
{
    public required string Id { get; set; }
    public required string Password { get; set; }
}

// ユーザー情報(デモ用)
internal record UserInfo(string Id, string Password, string Name, string Role);
