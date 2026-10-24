// Feature 0101 held-out (LLD 4.6), CWE-778 Concept A at the idiom level.
// The failure is set on a TaskCompletionSource, so whoever awaits its Task receives it.
// Every identifier is invented.
// HELD-OUT-TOKENS: TaskCompletionSource, TrySetException

class PrinterBridge
{
    void OnSpoolDone(TaskCompletionSource<int> tcs, SpoolJob job)
    {
        try
        {
            tcs.TrySetResult(job.PageCount());
        }
        catch (IOException ex) // EXPECT: clean
        {
            tcs.TrySetException(ex);
        }
    }

    void OnTokenRefreshed(TaskCompletionSource<string> tcs, TokenResponse response)
    {
        try
        {
            tcs.TrySetResult(tokenValidator.ValidateAccessToken(response));
        }
        catch (SecurityTokenException ex) // EXPECT: finding
        {
            tcs.TrySetException(ex);
        }
    }
}
