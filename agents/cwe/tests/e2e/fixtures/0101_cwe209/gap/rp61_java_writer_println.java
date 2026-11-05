class QuoteServlet {
    void doPost(Req req, Resp resp) throws Exception {
        try {
            price(req);
        } catch (Exception e) {
            PrintWriter out = resp.getWriter();
            // EXPECT-NEXT: clean  known-gap println is not a response-shaped verb
            out.println(e.toString());
        }
    }
}
