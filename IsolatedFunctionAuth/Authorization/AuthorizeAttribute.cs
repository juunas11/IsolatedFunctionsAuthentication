using System;

namespace IsolatedFunctionAuth.Authorization
{
    /// <summary>
    /// Set at Function class or method level to
    /// set what scopes/user roles/app roles are
    /// required in requests.
    /// </summary>
    /// <remarks>
    /// If you do not specify app roles, calls
    /// without user context will fail.
    /// Same goes for scopes/user roles;
    /// calls with user context will fail if
    /// both are not specified.
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AuthorizeAttribute : Attribute
    {
        /// <summary>
        /// Defines which scopes (aka delegated permissions)
        /// are accepted. In this sample these
        /// must be combined with <see cref="UserRoles"/>.
        /// </summary>
        public string[] Scopes { get; set; } = Array.Empty<string>();
        /// <summary>
        /// Defines which user roles are accpeted.
        /// Must be combined with <see cref="Scopes"/>.
        /// </summary>
        public string[] UserRoles { get; set; } = Array.Empty<string>();
        /// <summary>
        /// Defines which app roles (aka application permissions)
        /// are accepted.
        /// </summary>
        public string[] AppRoles { get; set; } = Array.Empty<string>();
    }
}
