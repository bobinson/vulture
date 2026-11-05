public class Svc {
    record Result(boolean ok, String error) {}
    private Result load(String id) {
        try { return new Result(true, null); }
        catch (Exception e) { return new Result(false, e.getMessage()); }
    }
    public void get(Context ctx, String id) {
        var r = this.load(id);
        ctx.json(Map.of("error", r.error())); // EXPECT: finding tp-java-this-call
    }
}
