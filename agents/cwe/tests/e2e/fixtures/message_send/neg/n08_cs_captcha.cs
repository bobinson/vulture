namespace Demo;

public class NewsletterEndpoint
{
    private readonly INotifier _notifier;
    private readonly ICaptchaVerifier _captcha;

    public async Task<IResult> Subscribe(SubscribeRequest body)
    {
        if (!await _captcha.VerifyAsync(body.CaptchaToken))
        {
            return Results.Accepted();
        }
        var email = body.Email.Trim();
        await _notifier.SendConfirmationEmailAsync(email);
        return Results.Accepted();
    }
}
