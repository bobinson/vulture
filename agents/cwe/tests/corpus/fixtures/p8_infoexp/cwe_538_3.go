package logging

import "gopkg.in/natefinch/lumberjack.v2"

func Rotator() *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   "www/access.log",
		MaxBackups: 7,
	}
}
