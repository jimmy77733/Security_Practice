using System.ComponentModel.DataAnnotations;

namespace Security_Practice.Models
{
    /// 註冊表單的視圖模型 - 包含完整的註冊資料驗證
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "名稱是必填的")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "名稱長度需要在3到50字符之間")]
        [RegularExpression(@"^[a-zA-Z0-9@#$]+$", ErrorMessage = "名稱只能包含字母、數字和@、#、$符號")]
        public string Username { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "電子郵件是必填的")]
        [EmailAddress(ErrorMessage = "請輸入有效的電子郵件地址")]
        public string Email { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "密碼是必填的")]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "密碼長度需要至少8個字符")]
        [RegularExpression(@"^[a-zA-Z0-9@#$]+$", ErrorMessage = "密碼只能包含字母、數字和@、#、$符號")]
        public string Password { get; set; } = string.Empty;
        
        [Required(ErrorMessage = "請確認密碼")]
        [Compare("Password", ErrorMessage = "密碼和確認密碼不匹配")]
        public string ConfirmPassword { get; set; } = string.Empty;
        
        [Phone(ErrorMessage = "請輸入有效的手機號碼")]
        [RegularExpression(@"^[0-9@#$-]+$", ErrorMessage = "手機號碼只能包含數字和@、#、$、-符號")]
        public string? PhoneNumber { get; set; }
    }
}
