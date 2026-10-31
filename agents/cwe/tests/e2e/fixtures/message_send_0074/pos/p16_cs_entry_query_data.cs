public class InviteController : Controller
{
    [HttpGet("invite")]
    public IActionResult Invite(InviteQueryData data)
    {
        _mailer.SendEmail(data.Email, "You are invited");
        return Ok();
    }
}
