using IsolatedFunctionAuth.Authorization;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IsolatedFunctionAuth.Middleware
{
    public class AuthorizationMiddleware : IFunctionsWorkerMiddleware
    {
        private const string ScopeClaimType = "http://schemas.microsoft.com/identity/claims/scope";

        public async Task Invoke(
            FunctionContext context,
            FunctionExecutionDelegate next)
        {
            var principalFeature = context.Features.Get<JwtPrincipalFeature>();
            if (!AuthorizePrincipal(context, principalFeature.Principal))
            {
                context.SetHttpResponseStatusCode(HttpStatusCode.Forbidden);
                return;
            }

            await next(context);
        }

        private static bool AuthorizePrincipal(FunctionContext context, ClaimsPrincipal principal)
        {
            // This authorization implementation was made
            // for Azure AD. Your identity provider might differ.

            if (principal.HasClaim(c => c.Type == ScopeClaimType))
            {
                // Request made with delegated permissions, check scopes and user roles
                return AuthorizeDelegatedPermissions(context, principal);
            }

            // Request made with application permissions, check app roles
            return AuthorizeApplicationPermissions(context, principal);
        }

        private static bool AuthorizeDelegatedPermissions(FunctionContext context, ClaimsPrincipal principal)
        {
            var targetMethod = context.GetTargetFunctionMethod();

            var (acceptedScopes, acceptedUserRoles) = GetAcceptedScopesAndUserRoles(targetMethod);

            var userRoles = principal.FindAll(ClaimTypes.Role);
            var userHasAcceptedRole = userRoles.Any(ur => acceptedUserRoles.Contains(ur.Value));

            var callerScopes = (principal.FindFirst(ScopeClaimType)?.Value ?? "")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var callerHasAcceptedScope = callerScopes.Any(cs => acceptedScopes.Contains(cs));

            // This app requires both a scope and user role
            // when called with scopes, so we check both
            return userHasAcceptedRole && callerHasAcceptedScope;
        }

        private static bool AuthorizeApplicationPermissions(FunctionContext context, ClaimsPrincipal principal)
        {
            var targetMethod = context.GetTargetFunctionMethod();

            var acceptedAppRoles = GetAcceptedAppRoles(targetMethod);
            var appRoles = principal.FindAll(ClaimTypes.Role);
            var appHasAcceptedRole = appRoles.Any(ur => acceptedAppRoles.Contains(ur.Value));
            return appHasAcceptedRole;
        }

        private static (List<string> scopes, List<string> userRoles) GetAcceptedScopesAndUserRoles(MethodInfo targetMethod)
        {
            var attributes = GetCustomAttributesOnClassAndMethod<AuthorizeAttribute>(targetMethod);
            // If scopes A and B are allowed at class level,
            // and scope A is allowed at method level,
            // then only scope A can be allowed.
            // This finds those common scopes and
            // user roles on the attributes.
            var scopes = attributes
                .Select(a => a.Scopes)
                .Aggregate(new List<string>().AsEnumerable(), (result, acceptedScopes) =>
                {
                    return result.Intersect(acceptedScopes);
                })
                .ToList();
            var userRoles = attributes
                .Select(a => a.UserRoles)
                .Aggregate(new List<string>().AsEnumerable(), (result, acceptedRoles) =>
                {
                    return result.Intersect(acceptedRoles);
                })
                .ToList();
            return (scopes, userRoles);
        }

        private static List<string> GetAcceptedAppRoles(MethodInfo targetMethod)
        {
            var attributes = GetCustomAttributesOnClassAndMethod<AuthorizeAttribute>(targetMethod);
            // Same as above for scopes and user roles,
            // only allow app roles that are common in
            // class and method level attributes.
            return attributes
                .Select(a => a.AppRoles)
                .Aggregate(new List<string>().AsEnumerable(), (result, acceptedRoles) =>
                {
                    return result.Intersect(acceptedRoles);
                })
                .ToList();
        }

        private static List<T> GetCustomAttributesOnClassAndMethod<T>(MethodInfo targetMethod)
            where T : Attribute
        {
            var methodAttributes = targetMethod.GetCustomAttributes<T>();
            var classAttributes = targetMethod.DeclaringType.GetCustomAttributes<T>();
            return methodAttributes.Concat(classAttributes).ToList();
        }
    }
}
