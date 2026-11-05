public class Outcome { public bool Ok; public string Error; }
public class HopEndpoint {
    static Outcome Fail(string msg) {
        return new Outcome { Ok = false, Error = msg };
    }

    static Outcome Load(string id) {
        try {
            Store.Read(id);
            return new Outcome { Ok = true };
        } catch (Exception ex) {
            return Fail(ex.Message);
        }
    }

    public async Task Show(HttpContext context, string id) {
        var outcome = Load(id);
        await context.Response.WriteAsync(outcome.Error); // EXPECT: finding tp-kr-F4-hop
    }
}
