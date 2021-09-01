using IsolatedFunctionAuth.Middleware;
using Microsoft.Extensions.Hosting;

namespace IsolatedFunctionAuth
{
    public class Program
    {
        public static void Main()
        {
            var host = new HostBuilder()
                .ConfigureFunctionsWorkerDefaults((context, builder) =>
                {
                    builder.UseMiddleware<AuthenticationMiddleware>();
                    builder.UseMiddleware<AuthorizationMiddleware>();
                })
                .Build();

            host.Run();
        }
    }
}