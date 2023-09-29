using IdentityManager.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Controllers
{
    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RolesController(ApplicationDbContext db, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [HttpGet]
        public IActionResult Index()
        {
            var roleList = _db.Roles.ToList();

            return View(roleList);
        }

        [HttpGet]
        public async Task<IActionResult> Upsert(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                // create
                return View();
            }
            else
            {
                // update
                var role = _db.Roles.FirstOrDefault(u => u.Id == id);
                return View(role);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole role)
        {
            if(await _roleManager.RoleExistsAsync(role.Name))
            {
                // error
                TempData[Constants.Notification.Error] = "Role already exists!";

                return RedirectToAction(nameof(Index));
            }

            if (string.IsNullOrEmpty(role.Id))
            {
                // create
                await _roleManager.CreateAsync(new IdentityRole { Name = role.Name });

                TempData[Constants.Notification.Success] = "Role created successfully";
            }
            else
            {
                // update
                var roleFromDb = _db.Roles.FirstOrDefault(r => r.Id == role.Id);
                roleFromDb.Name = role.Name;
                roleFromDb.NormalizedName = role.Name.ToUpper();

                var result = await _roleManager.UpdateAsync(roleFromDb);

                TempData[Constants.Notification.Success] = "Role updated successfully";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        // [Authorize(Policy = "OnlySuperAdminChecker")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == id);
            if (objFromDb == null)
            {
                TempData[Constants.Notification.Error] = "Role not found.";
                return RedirectToAction(nameof(Index));
            }

            var userRolesForThisRole = _db.UserRoles.Where(u => u.RoleId == id).Count();
            if (userRolesForThisRole > 0)
            {
                TempData[Constants.Notification.Error] = "Cannot delete this role, since there are users assigned to this role.";
                return RedirectToAction(nameof(Index));
            }

            await _roleManager.DeleteAsync(objFromDb);
            TempData[Constants.Notification.Success] = "Role deleted successfully.";
            return RedirectToAction(nameof(Index));

        }
    }
}
