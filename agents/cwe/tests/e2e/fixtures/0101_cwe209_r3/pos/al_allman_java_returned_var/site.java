class LedgerEndpoint
{
    static Map<String, String> load(String id)
    {
        try
        {
            store.read(id);
            return Map.of("ok", "true");
        }
        catch (Exception e)
        {
            Map<String, String> out = new HashMap<>();
            out.put("ok", "false");
            Outcome o = new Outcome();
            o.error = e.getMessage();
            return o;
        }
    }

    void show(HttpServletResponse response, String id) throws IOException
    {
        Outcome outcome = load(id);
        response.getWriter().write(outcome.error); // EXPECT: finding tp-allman-F1-returned-var
    }
}
