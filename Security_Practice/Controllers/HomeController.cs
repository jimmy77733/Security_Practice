using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Security_Practice.Controllers
{

    /// 首頁控制器 - 處理一般用戶頁面
    [Authorize] // 需要登入才能訪問
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
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
        public IActionResult Profile()
        {
            var userName = User.Identity?.Name;
            var userEmail = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
            var userRole = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;

            ViewBag.UserName = userName;
            ViewBag.UserEmail = userEmail;
            ViewBag.UserRole = userRole;

            return View();
        }


        /// 錯誤頁面
        [AllowAnonymous]
        public IActionResult Error()
        {
            return View();
        }
    }
}
