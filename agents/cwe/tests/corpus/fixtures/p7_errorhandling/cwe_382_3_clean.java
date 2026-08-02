import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

public class BootListener implements ServletContextListener {
  public void contextInitialized(ServletContextEvent event) {
    if (!configValid(event)) {
      throw new IllegalStateException("invalid configuration");
    }
  }
}
