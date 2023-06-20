using System.Net;
using Microsoft.Azure.Functions.Worker;

namespace IsolatedFunctionAuth.Middleware
{
    public static class FunctionContextExtensions
    {
        public static void SetHttpResponseStatusCode(this FunctionContext context, HttpStatusCode statusCode)
        {
            var response = context.GetHttpResponseData();
            if (response != null)
            {
                response.StatusCode = statusCode;
            }
        }
    }
}
