package notice

import "fmt"

func message(id int64, err error) string {
	return fmt.Sprintf("Delete repository %d local copy: %v", id, err) // EXPECT: clean
}
