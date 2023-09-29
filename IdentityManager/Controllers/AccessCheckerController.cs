using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.AccessControl;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        // accessible to all users 
        [AllowAnonymous]
        public IActionResult Index()
        {
            return View();
        }

        // accessible to authorized users
        [Authorize]
        public IActionResult AuthorizedAccess() 
        {
            return View();
        }

        // accessible to users with user role
        [Authorize(Roles = "User")]
        public IActionResult UserAccess() 
        {
            return View();
        }

        // accessible to users with user or admin role
        [Authorize(Roles = "User,Admin")]
        public IActionResult UserOrAdminAccess()
        {
            return View();
        }

        // accessible to users with admin role
        [Authorize(Policy = "Admin")]
        public IActionResult AdminAccess()
        {
            return View();
        }

        // accessible to users with admin and user role
        [Authorize(Policy = "UserAndAdmin")]
        public IActionResult UserAndAdminAccess()
        {
            return View();
        }

        // accessible to admin users with claim (create) to be true (AND not OR)
        [Authorize(Policy = "Admin_With_Create_Claim")]
        public IActionResult AdminWithCreateClaim()
        {
            return View();
        }

        // accessible to admin users with claim (create, edit, delete) to be true (AND not OR)
        [Authorize(Policy = "Admin_With_Create_Edit_Delete_Claim")]
        public IActionResult AdminWithCreateEditDeleteClaims()
        {
            return View();
        }

        // accessible to admin users with claim (create, edit, delete) to be true, Or in super admin role
        [Authorize(Policy = "Admin_With_Create_Edit_Delete_Claim_Or_SuperAdmin")]
        public IActionResult AdminWithCreateEditDeleteClaimsOrSuperAdmin()
        {
            return View();
        }
    }
}
