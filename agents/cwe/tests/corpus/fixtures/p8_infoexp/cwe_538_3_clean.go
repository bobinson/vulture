package logging

import "gopkg.in/natefinch/lumberjack.v2"

func Rotator() *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   "srv/state/access.log",
		MaxBackups: 7,
	}
}
