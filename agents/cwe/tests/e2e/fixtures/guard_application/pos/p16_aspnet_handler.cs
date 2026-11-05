using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

public class InternalRequirementHandler : AuthorizationHandler<InternalRequirement>
{
    private readonly IHttpContextAccessor _http;
    public InternalRequirementHandler(IHttpContextAccessor http) { _http = http; }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, InternalRequirement requirement)
    {
        var ctx = _http.HttpContext;
        if (ctx.Request.Headers.ContainsKey("X-Internal"))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}
