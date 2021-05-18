package glog

import "fmt"

func (l *loggingT) printLevel(level int, s severity, args ...interface{}) {
	l.printDepth(s, level, args...)
}

func (l *loggingT) printfLevel(level int, s severity, format string, args ...interface{}) {
	buf, file, line := l.header(s, level)
	fmt.Fprintf(buf, format, args...)
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
	l.output(s, buf, file, line, false)
}

func (v Verbose) _InfoLevel(level int, args ...interface{}) {
	if v.isEnabled {
		v.logger.printLevel(level, infoLog, args...)
	}
}

func (v Verbose) _InfofLevel(level int, format string, args ...interface{}) {
	if v.isEnabled {
		v.logger.printfLevel(level, infoLog, format, args...)
	}
}

// Debug is a convenience method to log at v=1.
func (l *loggingT) Debug(args ...interface{}) {
	l.V(1)._InfoLevel(2, args...)
}

// Debugf is a convenience method to log at v=1.
func (l *loggingT) Debugf(format string, args ...interface{}) {
	l.V(1)._InfofLevel(1, format, args...)
}

// Trace is a convenience method to log at v=2.
func (l *loggingT) Trace(args ...interface{}) {
	l.V(2)._InfoLevel(2, args...)
}

// Tracef is a convenience method to log at v=2.
func (l *loggingT) Tracef(format string, args ...interface{}) {
	l.V(2)._InfofLevel(1, format, args...)
}

// ===========================================
// Global functions exported.
// ===========================================

// Debug is a convenience method to log at v=1.
func Debug(args ...interface{}) {
	G.V(1)._InfoLevel(2, args...)
}

// Debugf is a convenience method to log at v=1.
func Debugf(format string, args ...interface{}) {
	G.V(1)._InfofLevel(1, format, args...)
}

// Trace is a convenience method to log at v=2.
func Trace(args ...interface{}) {
	G.V(2)._InfoLevel(2, args...)
}

// Tracef is a convenience method to log at v=2.
func Tracef(format string, args ...interface{}) {
	G.V(2)._InfofLevel(1, format, args...)
}
