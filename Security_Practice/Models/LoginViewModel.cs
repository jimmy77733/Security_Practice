using System.ComponentModel.DataAnnotations;

namespace Security_Practice.Models
{
    // 登入表單的視圖模型 - 用於接收和驗證登入資料
    public class LoginViewModel
    {
        [Required(ErrorMessage = "名稱是必填的")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "名稱長度需要在3到50字符之間")]
        public string Username { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "密碼是必填的")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "密碼長度需要至少6個字符")]
        public string Password { get; set; } = string.Empty;
        
        public bool RememberMe { get; set; } = false;
    }
}
