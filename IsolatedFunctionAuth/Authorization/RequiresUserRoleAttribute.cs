using System;

namespace IsolatedFunctionAuth.Authorization
{
    /// <summary>
    /// Allows this function to be called
    /// with one of the given user roles.
    /// Note this attribute is typically applied
    /// with <see cref="RequiresScopeAttribute"/>.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method)]
    public class RequiresUserRoleAttribute : Attribute
    {
        public RequiresUserRoleAttribute(params string[] acceptedRoles)
        {
            AcceptedRoles = acceptedRoles;
        }

        public string[] AcceptedRoles { get; }
    }
}
