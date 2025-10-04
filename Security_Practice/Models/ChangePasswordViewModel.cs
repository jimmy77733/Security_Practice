using System.ComponentModel.DataAnnotations;

namespace Security_Practice.Models
{
    public class ChangePasswordViewModel
    {
        [Required(ErrorMessage = "目前密碼為必填項")]
        [DataType(DataType.Password)]
        [Display(Name = "目前密碼")]
        public string OldPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "新密碼為必填項")]
        [StringLength(100, ErrorMessage = "{0} 的長度至少必須為 {2} 個字元。", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "新密碼")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$",
            ErrorMessage = "密碼必須包含至少一個大寫字母、一個小寫字母、一個數字和一個特殊字元。")]
        public string NewPassword { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "確認新密碼")]
        [Compare("NewPassword", ErrorMessage = "新密碼與確認密碼不相符。")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}