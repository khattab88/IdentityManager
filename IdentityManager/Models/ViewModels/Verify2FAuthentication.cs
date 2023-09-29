using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models.ViewModels
{
    public class Verify2FAuthentication
    {
        [Required]
        public string Code { get; set; }
        [Display(Name = "Remember me")]
        public bool RememberMe { get; set; }
        public string ReturnUrl { get; set; }
    }
}
