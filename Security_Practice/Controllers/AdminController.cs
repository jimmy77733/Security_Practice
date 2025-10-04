using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Security_Practice.Models;
using Security_Practice.Services;

namespace Security_Practice.Controllers
{

    /// 管理員控制器 - 只有管理員角色才能訪問
    [Authorize(Roles = "Admin")] // 只有 Admin 角色可以訪問
    public class AdminController : Controller
    {
        private readonly IUserService _userService;
        private readonly ILogger<AdminController> _logger;

        public AdminController(IUserService userService, ILogger<AdminController> logger)
        {
            _userService = userService;
            _logger = logger;
        }

        /// 管理員儀表板 - 顯示所有用戶資訊和統計數據
        public async Task<IActionResult> Dashboard()
        {
            try
            {
                var users = await _userService.GetAllUsersAsync();
                
                var viewModel = new AdminDashboardViewModel
                {
                    Users = users,
                    TotalUsers = users.Count,
                    AdminUsers = users.Count(u => u.Role == "Admin"),
                    RegularUsers = users.Count(u => u.Role == "User"),
                    LastUpdated = DateTime.UtcNow
                };

                var adminName = User.Identity?.Name;
                _logger.LogInformation("管理員 {AdminName} 訪問儀表板", adminName);

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "載入管理員儀表板時發生錯誤");
                TempData["ErrorMessage"] = "載入儀表板時發生錯誤";
                return RedirectToAction("Index", "Home");
            }
        }

        /// 用戶管理頁面
        public async Task<IActionResult> Users()
        {
            try
            {
                var users = await _userService.GetAllUsersAsync();
                return View(users);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "載入用戶列表時發生錯誤");
                TempData["ErrorMessage"] = "載入用戶列表時發生錯誤";
                return View(new List<User>());
            }
        }

        /// 系統統計資訊 (API 端點)
        [HttpGet]
        public async Task<IActionResult> GetStats()
        {
            try
            {
                var users = await _userService.GetAllUsersAsync();
                
                var stats = new
                {
                    TotalUsers = users.Count,
                    AdminUsers = users.Count(u => u.Role == "Admin"),
                    RegularUsers = users.Count(u => u.Role == "User"),
                    ActiveUsers = users.Count(u => u.IsActive),
                    RecentRegistrations = users.Count(u => u.CreatedAt > DateTime.UtcNow.AddDays(-7)),
                    LastUpdated = DateTime.UtcNow
                };

                return Json(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "獲取統計資訊時發生錯誤");
                return Json(new { error = "無法獲取統計資訊" });
            }
        }
    }
}
