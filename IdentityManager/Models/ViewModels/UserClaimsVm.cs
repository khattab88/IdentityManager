using System.Collections.Generic;

namespace IdentityManager.Models.ViewModels
{
    public class UserClaimsVm
    {
        public string UserId { get; set; }
        public List<UserClaim> Claims { get; set; }

        public UserClaimsVm()
        {
            Claims = new List<UserClaim>();
        }
    }

    public class UserClaim
    {
        public string ClaimType { get; set; }
        public bool IsSelected { get; set; }
    }
}
