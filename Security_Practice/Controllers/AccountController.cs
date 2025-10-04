using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Security_Practice.Models;
using Security_Practice.Services;
using System.Security.Claims;

namespace Security_Practice.Controllers
{

    /// 帳戶控制器 - 處理用戶註冊、登入和驗證相關功能
    public class AccountController : Controller
    {
        private readonly IUserService _userService;
        private readonly IJwtService _jwtService;
        private readonly ILogger<AccountController> _logger;

        public AccountController(IUserService userService, IJwtService jwtService, ILogger<AccountController> logger)
        {
            _userService = userService;
            _jwtService = jwtService;
            _logger = logger;
        }

        /// 顯示登入頁面
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        {
            // 如果已登入，重定向到首頁
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Index", "Home");
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        /// 處理登入提交 - 包含 JWT Token 生成
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                // 驗證用戶身份
                var user = await _userService.AuthenticateAsync(model.Username, model.Password);

                if (user == null)
                {
                    ModelState.AddModelError(string.Empty, "使用者名稱或密碼錯誤");
                    _logger.LogWarning("登入失敗: 使用者 {Username}", model.Username);
                    return View(model);
                }

                // 生成 JWT Tokens
                var accessToken = _jwtService.GenerateAccessToken(user);
                var refreshToken = _jwtService.GenerateRefreshToken();

                // 設定 JWT Token 到 Cookie (HttpOnly, Secure)
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true, // 防止 XSS 攻擊
                    Secure = true,   // 只能透過 HTTPS 傳輸
                    SameSite = SameSiteMode.Strict, // CSRF 保護
                    Expires = DateTimeOffset.UtcNow.AddDays(7) // Refresh Token 7天有效
                };

                Response.Cookies.Append("AccessToken", accessToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(15) // Access Token 15分鐘
                });

                Response.Cookies.Append("RefreshToken", refreshToken, cookieOptions);

                // 設定用戶身份認證
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Role, user.Role)
                };

                var claimsIdentity = new ClaimsIdentity(claims, "JWT");
                var authProperties = new Microsoft.AspNetCore.Authentication.AuthenticationProperties();

                await HttpContext.SignInAsync("Cookies", new ClaimsPrincipal(claimsIdentity), authProperties);

                _logger.LogInformation("用戶 {Username} 成功登入", user.Username);

                // 根據角色重定向
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }

                return user.Role == "Admin" ? RedirectToAction("Dashboard", "Admin") : RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "登入處理時發生錯誤");
                ModelState.AddModelError(string.Empty, "登入時發生錯誤，請稍後再試");
                return View(model);
            }
        }

        /// 顯示註冊頁面
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            // 如果已登入，重定向到首頁
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Index", "Home");
            }

            return View();
        }

        /// 處理註冊提交 - 包含完整的安全驗證
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                // 註冊新用戶
                var user = await _userService.RegisterAsync(model);

                _logger.LogInformation("新用戶 {Username} 註冊成功", user.Username);

                // 註冊成功後自動登入
                TempData["SuccessMessage"] = "註冊成功！請登入您的帳戶。";
                return RedirectToAction(nameof(Login));
            }
            catch (InvalidOperationException ex)
            {
                ModelState.AddModelError(string.Empty, ex.Message);
                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "註冊處理時發生錯誤");
                ModelState.AddModelError(string.Empty, "註冊時發生錯誤，請稍後再試");
                return View(model);
            }
        }

        /// 登出功能 - 清除所有認證資訊
        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            try
            {
                // 清除 JWT Tokens
                Response.Cookies.Delete("AccessToken");
                Response.Cookies.Delete("RefreshToken");

                // 清除身份認證
                await HttpContext.SignOutAsync("Cookies");

                _logger.LogInformation("用戶 {Username} 已登出", User.Identity?.Name);

                TempData["InfoMessage"] = "您已成功登出";
                return RedirectToAction(nameof(Login));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "登出時發生錯誤");
                return RedirectToAction(nameof(Login));
            }
        }

        /// AJAX 檢查使用者名稱是否可用
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> CheckUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return Json(new { available = false, message = "使用者名稱不能為空" });
            }

            var exists = await _userService.UsernameExistsAsync(username);
            return Json(new { available = !exists, message = exists ? "使用者名稱已存在" : "使用者名稱可用" });
        }


        /// AJAX 檢查電子郵件是否可用
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> CheckEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                return Json(new { available = false, message = "電子郵件不能為空" });
            }

            var exists = await _userService.EmailExistsAsync(email);
            return Json(new { available = !exists, message = exists ? "電子郵件已被註冊" : "電子郵件可用" });
        }
        
        /// 顯示更改密碼頁面
        [HttpGet]
        [Authorize]
        public IActionResult ChangePassword()
        {
            return View();
        }

        /// 處理更改密碼提交
        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
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
                    return Unauthorized("無法驗證用戶身份，請重新登入。");
                }

                var result = await _userService.ChangePasswordAsync(userId, model.OldPassword, model.NewPassword); // This line is correct, the error is in the IUserService interface.

                if (result)
                {
                    TempData["SuccessMessage"] = "密碼已成功更新！";
                    return RedirectToAction("Profile", "Home");
                }
                else
                {
                    ModelState.AddModelError("OldPassword", "目前的密碼不正確。");
                    return View(model);
                }
            }
            catch (InvalidOperationException ex)
            {
                ModelState.AddModelError(string.Empty, ex.Message);
                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "更改密碼時發生錯誤");
                ModelState.AddModelError(string.Empty, "更新密碼時發生未知錯誤，請稍後再試。");
                return View(model);
            }
        }

    }
}
