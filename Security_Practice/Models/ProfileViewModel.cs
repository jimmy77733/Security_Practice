using System.ComponentModel.DataAnnotations;

namespace Security_Practice.Models
{
    public class ProfileViewModel
    {
        [Required(ErrorMessage = "使用者名稱為必填項")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "使用者名稱長度必須介於 3 到 50 個字元之間")]
        [RegularExpression("^[a-zA-Z0-9_.-]+$", ErrorMessage = "使用者名稱只能包含字母、數字、底線、點和連字號")]
        [Display(Name = "使用者名稱")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "電子郵件為必填項")]
        [EmailAddress(ErrorMessage = "請輸入有效的電子郵件地址")]
        [StringLength(255)]
        [Display(Name = "電子郵件")]
        public string Email { get; set; } = string.Empty;
    }
}