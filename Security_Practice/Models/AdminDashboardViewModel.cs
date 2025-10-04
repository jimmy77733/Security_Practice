namespace Security_Practice.Models
{
    /// <summary>
    /// 管理員儀表板視圖模型 - 顯示所有用戶資訊
    /// </summary>
    public class AdminDashboardViewModel
    {
        public List<User> Users { get; set; } = new List<User>();
        public int TotalUsers { get; set; }
        public int AdminUsers { get; set; }
        public int RegularUsers { get; set; }
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
    }
}
