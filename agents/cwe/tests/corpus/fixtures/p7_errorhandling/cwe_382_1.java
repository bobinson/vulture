import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

public class MaintenanceServlet extends HttpServlet {
  protected void doPost(HttpServletRequest req) {
    if (req.getParameter("halt") != null) {
      System.exit(0);
    }
  }
}
