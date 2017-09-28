using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Identity
{
    public class RavenDbIdentityUser : IdentityUser<string>
    {
        private List<IdentityUserLogin<string>> _logins;
        private List<IdentityRole<string>> _roles;
        private List<IdentityUserClaim<string>> _claims;
        private List<IdentityUserToken<string>> _tokens;

        public List<IdentityUserLogin<string>> Logins
        {
            get => _logins;
            set => _logins.AddRange(value);
        }

        public List<IdentityRole<string>> Roles
        {
            get => _roles;
            set => _roles.AddRange(value);
        }

        public List<IdentityUserClaim<string>> Claims
        {
            get => _claims;
            set => _claims.AddRange(value);
        }

        public List<IdentityUserToken<string>> Tokens
        {
            get => _tokens;
            set => _tokens.AddRange(value);
        }

        public RavenDbIdentityUser()
        {
            _logins = new List<IdentityUserLogin<string>>();
            _roles = new List<IdentityRole<string>>();
            _claims = new List<IdentityUserClaim<string>>();
            _tokens = new List<IdentityUserToken<string>>();
        }
    }
}
