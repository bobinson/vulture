import javax.servlet.http.HttpServletRequest;

class A {
    void f(HttpServletRequest req) throws Exception {
        Runtime r = Runtime.getRuntime();
        r.exec(req.getParameter("cmd")); // EXPECT: finding
    }
}
