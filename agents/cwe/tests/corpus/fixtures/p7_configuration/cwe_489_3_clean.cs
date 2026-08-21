using System.Diagnostics;

public class Startup {
    public void Configure() {
#if DEBUG
        Debugger.Launch();
#endif
    }
}
