using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Security_Practice.Data;
using Security_Practice.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 設定資料庫連接
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// 註冊服務
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IJwtService, JwtService>();

// 設定 JWT 驗證
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT Secret Key not configured");
var key = Encoding.ASCII.GetBytes(secretKey);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = "JWT";
})
.AddJwtBearer("JWT", options =>
{
    options.RequireHttpsMetadata = true; // 強制 HTTPS
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidateAudience = true,
        ValidAudience = jwtSettings["Audience"],
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero // 不允許時鐘偏差
    };

    // 從 Cookie 中讀取 JWT Token
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var token = context.Request.Cookies["AccessToken"];
            if (!string.IsNullOrEmpty(token))
            {
                context.Token = token;
            }
            return Task.CompletedTask;
        }
    };
});

// 設定授權策略 (RBAC - Role-Based Access Control)
builder.Services.AddAuthorization(options =>
{
    // 管理員專用策略
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin").RequireAuthenticatedUser());
    
    // 用戶或管理員策略
    options.AddPolicy("UserOrAdmin", policy =>
        policy.RequireRole("User", "Admin").RequireAuthenticatedUser());
    
    // 需要驗證的一般策略
    options.AddPolicy("Authenticated", policy =>
        policy.RequireAuthenticatedUser());
});

// 加入 MVC 支援
builder.Services.AddControllersWithViews(options =>
{
    // 全域防偽造令牌過濾器
    options.Filters.Add(new Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute());
});

// 設定 HTTPS 重定向
builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
    options.HttpsPort = 5001; // 根據您的設定調整
});

// 設定 HSTS (HTTP Strict Transport Security)
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});

var app = builder.Build();

// 設定 HTTP 請求管道
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts(); // 生產環境使用 HSTS
}

// 強制 HTTPS
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// 啟用身份驗證和授權
app.UseAuthentication();
app.UseAuthorization();

// 設定路由
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

// 初始化資料庫並建立預設管理員帳戶
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        var userService = services.GetRequiredService<IUserService>();
        await DbInitializer.InitializeAsync(context, userService);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "初始化資料庫時發生錯誤");
    }
}

app.Run();
