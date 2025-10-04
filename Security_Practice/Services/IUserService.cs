using Security_Practice.Models;

namespace Security_Practice.Services
{
    /// 用戶服務介面 - 定義用戶相關操作

    public interface IUserService
    {
        Task<User?> AuthenticateAsync(string username, string password);
        Task<User> RegisterAsync(RegisterViewModel model);
        Task<User?> GetUserByUsernameAsync(string username);
        Task<User?> GetUserByIdAsync(int id);
        Task<List<User>> GetAllUsersAsync();
        Task<bool> UsernameExistsAsync(string username);
        Task<bool> EmailExistsAsync(string email);
        string HashPassword(string password);
        bool VerifyPassword(string password, string hashedPassword);
        string SanitizeInput(string input);
        Task UpdateProfileAsync(int userId, string username, string email);
        Task<bool> ChangePasswordAsync(int userId, string oldPassword, string newPassword);
    }
}
