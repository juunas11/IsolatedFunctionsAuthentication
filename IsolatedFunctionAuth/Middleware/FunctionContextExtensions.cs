using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using System;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Threading.Tasks;

namespace IsolatedFunctionAuth.Middleware
{
    public static class FunctionContextExtensions
    {
        public static async Task SetHttpResponseStatusCode(
            this FunctionContext context,
            HttpStatusCode statusCode)
        {
            var req = await context.GetHttpRequestDataAsync();
            if (req == null) { return; }
            var response = HttpResponseData.CreateResponse(req);
            response.StatusCode = statusCode;
            var result = context.GetInvocationResult();
            result.Value = response;
        }

        public static MethodInfo GetTargetFunctionMethod(this FunctionContext context)
        {
            // More terrible reflection code..
            // Would be nice if this was available out of the box on FunctionContext

            // This contains the fully qualified name of the method
            // E.g. IsolatedFunctionAuth.TestFunctions.ScopesAndAppRoles
            var entryPoint = context.FunctionDefinition.EntryPoint;

            var assemblyPath = context.FunctionDefinition.PathToAssembly;
            var assembly = Assembly.LoadFrom(assemblyPath);
            var typeName = entryPoint.Substring(0, entryPoint.LastIndexOf('.'));
            var type = assembly.GetType(typeName);
            var methodName = entryPoint.Substring(entryPoint.LastIndexOf('.') + 1);
            var method = type.GetMethod(methodName);
            return method;
        }
    }
}
