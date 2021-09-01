using IsolatedFunctionAuth.Authorization;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using System;
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
            // This app requires both a scope and user role
            // when called with scopes
            var targetMethod = context.GetTargetFunctionMethod();

            var acceptedUserRoles = GetAcceptedUserRoles(context, targetMethod);
            var userRoles = principal.FindAll(ClaimTypes.Role);
            var userHasAcceptedRole = userRoles.Any(ur => acceptedUserRoles.Contains(ur.Value));

            var acceptedScopes = GetAcceptedScopes(context, targetMethod);
            var callerScopes = (principal.FindFirst(ScopeClaimType)?.Value ?? "")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var callerHasAcceptedScope = callerScopes.Any(cs => acceptedScopes.Contains(cs));

            return userHasAcceptedRole && callerHasAcceptedScope;
        }

        private static bool AuthorizeApplicationPermissions(FunctionContext context, ClaimsPrincipal principal)
        {
            var targetMethod = context.GetTargetFunctionMethod();

            var acceptedAppRoles = GetAcceptedAppRoles(context, targetMethod);
            var appRoles = principal.FindAll(ClaimTypes.Role);
            var appHasAcceptedRole = appRoles.Any(ur => acceptedAppRoles.Contains(ur.Value));
            return appHasAcceptedRole;
        }

        private static string[] GetAcceptedUserRoles(FunctionContext context, MethodInfo targetMethod)
        {
            var entryPoint = context.FunctionDefinition.EntryPoint;

            var attributes = targetMethod.GetCustomAttributes<RequiresUserRoleAttribute>().ToList();
            if (attributes.Count == 0)
            {
                return Array.Empty<string>();
            }
            if (attributes.Count > 1)
            {
                throw new Exception($"Function {entryPoint} has more than one [RequiresUserRole] attribute");
            }

            var acceptedRoles = attributes[0].AcceptedRoles;
            return acceptedRoles;
        }

        private static string[] GetAcceptedScopes(FunctionContext context, MethodInfo targetMethod)
        {
            var entryPoint = context.FunctionDefinition.EntryPoint;

            var attributes = targetMethod.GetCustomAttributes<RequiresScopeAttribute>().ToList();
            if (attributes.Count == 0)
            {
                return Array.Empty<string>();
            }
            if (attributes.Count > 1)
            {
                throw new Exception($"Function {entryPoint} has more than one [RequiresScope] attribute");
            }

            var acceptedScopes = attributes[0].AcceptedScopes;
            return acceptedScopes;
        }

        private static string[] GetAcceptedAppRoles(FunctionContext context, MethodInfo targetMethod)
        {
            var entryPoint = context.FunctionDefinition.EntryPoint;

            var attributes = targetMethod.GetCustomAttributes<RequiresAppRoleAttribute>().ToList();
            if (attributes.Count == 0)
            {
                return Array.Empty<string>();
            }
            if (attributes.Count > 1)
            {
                throw new Exception($"Function {entryPoint} has more than one [RequiresAppRole] attribute");
            }

            var acceptedRoles = attributes[0].AcceptedRoles;
            return acceptedRoles;
        }
    }
}
