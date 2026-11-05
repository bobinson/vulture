package x;

public class JavaRec {
    record Result(boolean ok, String error) {}

    Result load(String id) {
        try {
            return new Result(true, null);
        } catch (Exception e) {
            return new Result(false, e.getMessage());
        }
    }

    public void get(Context ctx, String id) {
        Result r = load(id);
        if (!r.ok()) {
            ctx.json(Map.of("error", r.error())); // probe tp-java-record-accessor
        }
    }

    static class Res2 { String error; String getError() { return error; } }

    Res2 load2(String id) {
        Res2 r = new Res2();
        try { x(); } catch (Exception e) { r.error = e.getMessage(); }
        return r;
    }

    public void get2(Context ctx, String id) {
        Res2 r = load2(id);
        ctx.json(Map.of("error", r.getError())); // EXPECT: finding tp-java-getter
    }
}
