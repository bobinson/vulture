package m
import "net/http"
import "database/sql"
import "fmt"
import "os/exec"
func f(r *http.Request) { exec.Command("sh", "-c", r.FormValue("c")).Run() } // EXPECT: finding
