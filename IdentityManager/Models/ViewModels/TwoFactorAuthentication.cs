using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models.ViewModels
{
    public class TwoFactorAuthentication
    {
        //used to login
        public string Code { get; set; }

        //used to register / signup
        public string Token { get; set; }
        public string QRCodeUrl { get; set; }
    }
}
