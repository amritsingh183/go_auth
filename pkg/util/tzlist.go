package util

import (
	"fmt"
	"io/ioutil"
	"strings"
)

var zoneDirs = []string{
	"/usr/share/zoneinfo/",
	"/usr/share/lib/zoneinfo/",
	"/usr/lib/locale/TZ/",
}

var zoneDir string

// PrintTimezones PrintTimezones
func PrintTimezones() {
	for _, zoneDir = range zoneDirs {
		ParseTZFiles("")
	}
}

// ParseTZFiles ParseTZFiles
func ParseTZFiles(path string) {
	files, _ := ioutil.ReadDir(zoneDir + path)
	for _, f := range files {
		if f.Name() != strings.ToUpper(f.Name()[:1])+f.Name()[1:] {
			continue
		}
		if f.IsDir() {
			ParseTZFiles(path + "/" + f.Name())
		} else {
			fmt.Println((path + "/" + f.Name())[1:])
		}
	}
}
