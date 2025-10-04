using Microsoft.EntityFrameworkCore;
using Security_Practice.Data;
using Security_Practice.Models;
using System.Text.RegularExpressions;

namespace Security_Practice.Services
{
    /// 用戶服務實作 - 處理用戶註冊、登入驗證和資料管理
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<UserService> _logger;
        
        // OWASP 建議：只允許安全字符的正則表達式
        private static readonly Regex AllowedCharactersRegex = new Regex(@"^[a-zA-Z0-9@#$\-\.]+$", RegexOptions.Compiled);

        public UserService(ApplicationDbContext context, ILogger<UserService> logger)
        {
            _context = context;
            _logger = logger;
        }


        /// 用戶身份驗證 - 使用 BCrypt 驗證密碼雜湊
        public async Task<User?> AuthenticateAsync(string username, string password)
        {
            try
            {
                // 清理輸入資料
                username = SanitizeInput(username);
                
                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                    return null;

                // 使用參數化查詢防止 SQL 注入攻擊
                var user = await _context.Users
                    .Where(u => u.Username == username && u.IsActive)
                    .FirstOrDefaultAsync();

                if (user != null && VerifyPassword(password, user.PasswordHash))
                {
                    _logger.LogInformation("用戶 {Username} 成功登入", username);
                    return user;
                }

                _logger.LogWarning("用戶 {Username} 登入失敗", username);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "驗證用戶 {Username} 時發生錯誤", username);
                return null;
            }
        }


        /// 註冊新用戶 - 包含完整的輸入驗證和安全措施
        public async Task<User> RegisterAsync(RegisterViewModel model)
        {
            try
            {
                // 清理和驗證輸入資料
                model.Username = SanitizeInput(model.Username);
                model.Email = SanitizeInput(model.Email);
                
                if (!string.IsNullOrEmpty(model.PhoneNumber))
                    model.PhoneNumber = SanitizeInput(model.PhoneNumber);

                // 檢查用戶名和郵箱是否已存在
                if (await UsernameExistsAsync(model.Username))
                    throw new InvalidOperationException("使用者名稱已存在");

                if (await EmailExistsAsync(model.Email))
                    throw new InvalidOperationException("電子郵件已被註冊");

                // 建立新用戶
                var user = new User
                {
                    Username = model.Username,
                    Email = model.Email,
                    PasswordHash = HashPassword(model.Password),
                    PhoneNumber = model.PhoneNumber,
                    Role = "User", // 預設角色
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                _logger.LogInformation("新用戶 {Username} 註冊成功", model.Username);
                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "註冊用戶 {Username} 時發生錯誤", model.Username);
                throw;
            }
        }


        /// 根據使用者名稱查找用戶
        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            username = SanitizeInput(username);
            return await _context.Users
                .Where(u => u.Username == username)
                .FirstOrDefaultAsync();
        }


        /// 根據 ID 查找用戶
        public async Task<User?> GetUserByIdAsync(int id)
        {
            return await _context.Users.FindAsync(id);
        }


        /// 獲取所有用戶列表 (僅管理員可用)
        public async Task<List<User>> GetAllUsersAsync()
        {
            return await _context.Users
                .OrderBy(u => u.Username)
                .ToListAsync();
        }

        /// 檢查使用者名稱是否已存在
        public async Task<bool> UsernameExistsAsync(string username)
        {
            username = SanitizeInput(username);
            return await _context.Users
                .AnyAsync(u => u.Username == username);
        }

        /// 檢查電子郵件是否已存在
        public async Task<bool> EmailExistsAsync(string email)
        {
            email = SanitizeInput(email);
            return await _context.Users
                .AnyAsync(u => u.Email == email);
        }

        /// 使用 BCrypt 雜湊密碼 - 遵循 OWASP 建議
        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, BCrypt.Net.BCrypt.GenerateSalt(12));
        }

        /// 驗證密碼雜湊
        public bool VerifyPassword(string password, string hashedPassword)
        {
            try
            {
                return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
            }
            catch
            {
                return false;
            }
        }

        /// 清理用戶輸入 - 防止 XSS 和注入攻擊
        /// OWASP 建議：只允許安全字符，移除潛在有害內容
        public string SanitizeInput(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            // 移除前後空白
            input = input.Trim();

            // 檢查是否只包含允許的字符
            if (!AllowedCharactersRegex.IsMatch(input))
            {
                // 移除不允許的字符
                input = Regex.Replace(input, @"[^a-zA-Z0-9@#$\-\.]", "");
            }

            // 防止常見的攻擊模式
            var dangerousPatterns = new[]
            {
                @"<script.*?>.*?</script>",
                @"javascript:",
                @"vbscript:",
                @"onload\s*=",
                @"onerror\s*=",
                @"onclick\s*=",
                @"<.*?>",
                @"&lt;.*?&gt;",
                @"exec\s*\(",
                @"eval\s*\(",
                @"union\s+select",
                @"drop\s+table",
                @"delete\s+from",
                @"insert\s+into",
                @"update\s+set"
            };

            foreach (var pattern in dangerousPatterns)
            {
                input = Regex.Replace(input, pattern, "", RegexOptions.IgnoreCase);
            }

            return input;
        }
    }
}