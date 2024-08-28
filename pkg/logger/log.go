package logger

import (
	"flag"
	"fmt"
	"runtime"

	"amritsingh374.bitbucket.org/cloud/auth/pkg/config"

	"k8s.io/klog/v2"
)

// Bootstrap ...
func Bootstrap(c *config.Logs) {
	klog.InitFlags(nil)
	klog.MaxSize = c.MaxSize
	flag.Set("logtostderr", "false")
	if c.LogToStdErr {
		flag.Set("logtostderr", "true")
	}
	flag.Set("alsologtostderr", "false")
	if c.LogToStdErr {
		flag.Set("alsologtostderr", "true")
	}
	flag.Set("log_file", c.LogFileName)
	flag.Parse()
}

// HandleError The error handler
func HandleError(err error, message string, severity string) {
	function, _, line, _ := runtime.Caller(1)
	l := fmt.Sprintf("%s:%d", runtime.FuncForPC(function).Name(), line)
	klog.Info(l)
	if err != nil {
		Log(l, err.Error())
		Log(l, message)
		switch severity {
		case "fatal":
			klog.Fatal(message)
		}
	}
}

// Log logs messages
// We may choose to Log to file
// or anywhere else
func Log(args ...interface{}) {
	function, _, line, _ := runtime.Caller(1)
	l := fmt.Sprintf("%s:%d", runtime.FuncForPC(function).Name(), line)
	args = append(args, " -- ", l)
	klog.Info(args...)
	klog.Flush()
}
