namespace Demo;

[Authorize]
public class TeamEndpoint
{
    private readonly INotifier _notifier;

    public async Task<IResult> Invite(InviteRequest body)
    {
        var email = body.Email.Trim();
        await _notifier.SendInvitationEmailAsync(email);
        return Results.Accepted();
    }
}
