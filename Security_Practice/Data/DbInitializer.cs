using Microsoft.EntityFrameworkCore;
using Security_Practice.Models;
using Security_Practice.Services;

namespace Security_Practice.Data
{

    /// 資料庫初始化器 - 建立預設管理員帳戶
    public static class DbInitializer
    {
        public static async Task InitializeAsync(ApplicationDbContext context, IUserService userService)
        {
            // 確保資料庫已建立
            await context.Database.EnsureCreatedAsync();

            // 如果已有用戶，則不需要初始化
            if (await context.Users.AnyAsync())
            {
                return;
            }

            // 建立預設管理員帳戶
            var adminUser = new User
            {
                Username = "admin",
                Email = "admin@security-practice.com",
                PasswordHash = userService.HashPassword("Admin123#"),
                PhoneNumber = "0912345678",
                Role = "Admin",
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            // 建立測試用戶帳戶
            var testUser = new User
            {
                Username = "testuser",
                Email = "test@security-practice.com",
                PasswordHash = userService.HashPassword("Test123#"),
                PhoneNumber = "0987654321",
                Role = "User",
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            context.Users.AddRange(adminUser, testUser);
            await context.SaveChangesAsync();
        }
    }
}
