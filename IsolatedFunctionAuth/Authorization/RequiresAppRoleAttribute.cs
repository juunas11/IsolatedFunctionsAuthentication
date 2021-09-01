using System;

namespace IsolatedFunctionAuth.Authorization
{
    /// <summary>
    /// Allows this function to be called with one of the given
    /// app roles, aka application permissions.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method)]
    public class RequiresAppRoleAttribute : Attribute
    {
        public RequiresAppRoleAttribute(params string[] acceptedRoles)
        {
            AcceptedRoles = acceptedRoles;
        }

        public string[] AcceptedRoles { get; }
    }
}
