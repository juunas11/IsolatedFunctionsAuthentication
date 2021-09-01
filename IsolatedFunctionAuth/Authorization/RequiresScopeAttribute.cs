using System;

namespace IsolatedFunctionAuth.Authorization
{
    /// <summary>
    /// Allows this function to be called with one of the given
    /// scopes, aka delegated permissions.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method)]
    public class RequiresScopeAttribute : Attribute
    {
        public RequiresScopeAttribute(params string[] acceptedScopes)
        {
            AcceptedScopes = acceptedScopes;
        }

        public string[] AcceptedScopes { get; }
    }
}
