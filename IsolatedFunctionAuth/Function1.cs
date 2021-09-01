using System.Net;
using IsolatedFunctionAuth.Authorization;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

namespace IsolatedFunctionAuth
{
    public static class Function1
    {
        // This function can be called with both scopes and app roles
        [RequiresScope(Scopes.FunctionsAccess)]
        [RequiresUserRole(UserRoles.User)]
        [RequiresAppRole(AppRoles.AccessAllFunctions)]
        [Function("ScopesAndAppRoles")]
        public static HttpResponseData ScopesAndAppRoles(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequestData req,
            FunctionContext executionContext)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");

            response.WriteString("Can be called with scopes or app roles");

            return response;
        }

        // This function can only be called with scopes
        [RequiresScope(Scopes.FunctionsAccess)]
        [RequiresUserRole(UserRoles.User)]
        [Function("OnlyScopes")]
        public static HttpResponseData OnlyScopes(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequestData req,
            FunctionContext executionContext)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");

            response.WriteString("Can be called with scopes only");

            return response;
        }

        // This function can only be called with app roles
        [RequiresAppRole(AppRoles.AccessAllFunctions)]
        [Function("OnlyAppRoles")]
        public static HttpResponseData OnlyAppRoles(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequestData req,
            FunctionContext executionContext)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");

            response.WriteString("Can be called with app roles only");

            return response;
        }
    }
}
