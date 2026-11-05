public class Outcome { public bool Ok; public string Error; }
public class JobEndpoint {
    static Outcome Run(string id) {
        try {
            Work(id);
            return new Outcome { Ok = true };
        }
        catch (Exception ex) {
            Jobs.Save(new Job { Id = id, Error = ex.Message });
            return new Outcome { Ok = false, Error = "JOB_FAILED" };
        }
    }

    public async Task Show(HttpContext context, string id) {
        var outcome = Run(id);
        await context.Response.WriteAsync(outcome.Error); // EXPECT: clean clean-kr-persisted
    }
}
