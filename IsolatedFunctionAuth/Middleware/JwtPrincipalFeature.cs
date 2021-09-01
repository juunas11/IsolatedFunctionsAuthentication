using System.Security.Claims;

namespace IsolatedFunctionAuth.Middleware
{
    public class JwtPrincipalFeature
    {
        public JwtPrincipalFeature(ClaimsPrincipal principal, string accessToken)
        {
            Principal = principal;
            AccessToken = accessToken;
        }

        public ClaimsPrincipal Principal { get; }
        public string AccessToken { get; }
    }
}
