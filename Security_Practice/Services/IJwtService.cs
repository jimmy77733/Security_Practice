using Security_Practice.Models;

namespace Security_Practice.Services
{

    /// JWT 服務介面 - 定義 JWT token 相關操作
    public interface IJwtService
    {
        string GenerateAccessToken(User user);
        string GenerateRefreshToken();
        bool ValidateToken(string token);
        string? GetUsernameFromToken(string token);
        string? GetRoleFromToken(string token);
    }
}
