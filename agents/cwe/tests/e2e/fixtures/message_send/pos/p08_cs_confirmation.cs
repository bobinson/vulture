namespace Demo;

public class NewsletterEndpoint
{
    private readonly INotifier _notifier;

    public NewsletterEndpoint(INotifier notifier) => _notifier = notifier;

    public async Task<IResult> Subscribe(SubscribeRequest body)
    {
        var email = body.Email.Trim();
        await _notifier.SendConfirmationEmailAsync(email);
        return Results.Accepted();
    }
}
