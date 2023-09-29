using IdentityManager.Data;
using IdentityManager.Services.Email;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));
            });

            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders()
                .AddDefaultUI();

            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequiredLength = 5;
                options.Password.RequireLowercase = true;

                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
                options.Lockout.MaxFailedAccessAttempts = 2;

                options.SignIn.RequireConfirmedEmail = true;
            });

            //services.ConfigureApplicationCookie(options => {
            //    options.AccessDeniedPath = new Microsoft.AspNetCore.Http.PathString("/Home/AccessDenied");
            //});

            services.AddAuthentication().AddFacebook(options =>
            {
                options.AppId = "842033964309779";
                options.AppSecret = "4950e23e2563d57ac09903c890df06bf";
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
                options.AddPolicy("UserAndAdmin", policy => policy.RequireRole("User").RequireRole("Admin"));

                options.AddPolicy("Admin_With_Create_Claim",
                    policy => policy.RequireRole("Admin").RequireClaim("Create", "True"));

                options.AddPolicy("Admin_With_Create_Edit_Delete_Claim",
                    policy => policy.RequireRole("Admin")
                    .RequireClaim("Create", "True")
                    .RequireClaim("Edit", "True")
                    .RequireClaim("Delete", "True")
                    );

                options.AddPolicy("Admin_With_Create_Edit_Delete_Claim_Or_SuperAdmin", policy => policy.RequireAssertion(context =>
                (
                    context.User.IsInRole("Admin") &&
                    context.User.HasClaim(c => c.Type == "Create" && c.Value == "True") &&
                    context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True") &&
                    context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
                ) || context.User.IsInRole("SuperAdmin") 
                ));
            });

            services.Configure<MailSettings>(Configuration.GetSection("MailSettings"));

            services.AddTransient<IEmailSender, MailService>();

            services.AddControllersWithViews();
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");

                endpoints.MapRazorPages();
            });
        }
    }
}
