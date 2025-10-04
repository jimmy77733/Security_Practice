using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Security_Practice.Models;
using Security_Practice.Services;
using System.Security.Claims;

namespace Security_Practice.Controllers
{

    /// 首頁控制器 - 處理一般用戶頁面
    [Authorize] // 需要登入才能訪問
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IUserService _userService;
        private readonly IJwtService _jwtService;

        public HomeController(ILogger<HomeController> logger, IUserService userService, IJwtService jwtService)
        {
            _logger = logger;
            _userService = userService;
            _jwtService = jwtService;
        }

        /// 用戶首頁 - 顯示歡迎訊息和基本功能
        public IActionResult Index()
        {
            // 獲取當前用戶資訊
            var userName = User.Identity?.Name;
            var userRole = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;

            ViewBag.UserName = userName;
            ViewBag.UserRole = userRole;
            ViewBag.CurrentTime = DateTime.Now;

            _logger.LogInformation("用戶 {UserName} 訪問首頁", userName);

            return View();
        }

        /// 用戶資料頁面
        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            var userIdValue = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userIdValue) || !int.TryParse(userIdValue, out var userId))
            {
                return Unauthorized();
            }

            var user = await _userService.GetUserByIdAsync(userId);

            if (user == null)
            {
                return NotFound();
            }

            var model = new ProfileViewModel
            {
                Username = user.Username,
                Email = user.Email
            };

            return View(model);
        }

        /// 處理用戶資料更新
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Profile(ProfileViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                var userIdValue = User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(userIdValue) || !int.TryParse(userIdValue, out var userId))
                {
                    // 如果用戶已通過 [Authorize] 驗證，但我們卻找不到 ID，這是一個異常情況。
                    _logger.LogWarning("已驗證的用戶無法從 Claims 中獲取有效的用戶 ID。");
                    return Unauthorized("無法驗證用戶身份，請重新登入。");
                }

                await _userService.UpdateProfileAsync(userId, model.Username, model.Email);

                TempData["SuccessMessage"] = "個人資料更新成功！";
                _logger.LogInformation("用戶 {UserId} 更新了個人資料", userId);

                return RedirectToAction(nameof(Profile));
            }
            catch (InvalidOperationException ex)
            {
                ModelState.AddModelError(string.Empty, ex.Message);
                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "更新個人資料時發生錯誤");
                ModelState.AddModelError(string.Empty, "更新時發生未知錯誤，請稍後再試。");
                return View(model);
            }
        }


        /// 錯誤頁面
        [AllowAnonymous]
        public IActionResult Error()
        {
            return View();
        }
    }

}
