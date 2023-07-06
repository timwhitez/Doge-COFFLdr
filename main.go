package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/timwhitez/Doge-CoffLdr/pkg/coff"
)

func main() {
	rawCoff, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	var config []byte

	if len(os.Args) == 3 {
		config, _ = ioutil.ReadFile(os.Args[2])
	}

	outdata, err := coff.LoadAndRun(rawCoff, config)

	if outdata != "" {
		fmt.Printf("Outdata Below:\n\n%s\n", outdata)
	}
	if err != nil {
		fmt.Errorf("Error Msg:\n\n%s\n", err)
	}
}