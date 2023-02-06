package config

import (
	"fmt"
	"time"
)

func parseTime(s string) (time.Time, error) {
	for _, format := range formats {
		t, err := time.Parse(format, s)
		if err == nil {
			return t, nil
		}
	}
	return time.Now(), fmt.Errorf("invalid time format: %s", s)
}

var formats = []string{
	time.RFC3339,
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	"2006-01-02",
}
