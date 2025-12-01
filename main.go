package main

import (
	"fmt"
	"os"
	"strings"

	peparser "github.com/saferwall/pe"
)

func usage() {
	fmt.Println("Usage: analyzer <file.exe|file.dll>")
	fmt.Println("Example: analyzer C:\\Binaries\\notepad.exe")
}

// analyzePE открывает и парсит PE-файл и выводит простую информацию о секциях.
func analyzePE(filename string) error {
	pe, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}

	if err := pe.Parse(); err != nil {
		return fmt.Errorf("error parsing PE: %w", err)
	}

	fmt.Printf("Successfully parsed %s\n", filename)
	fmt.Printf("Number of sections: %d\n", len(pe.Sections))

	for _, sec := range pe.Sections {
		//fmt.Printf("Section Name : %s\n", sec.NameString())
		fmt.Printf("Section VirtualSize : %x\n", sec.Header.VirtualSize)
		fmt.Printf("Section Flags : %x, Meaning: %v\n\n",
			sec.Header.Characteristics, sec.PrettySectionFlags())
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		fmt.Println("No arguments provided")
		return
	}

	firstArgument := os.Args[1]

	if firstArgument == "help" || firstArgument == "--help" || firstArgument == "-h" {
		usage()
		return
	}

	lower := strings.ToLower(firstArgument)
	if !strings.Contains(lower, ".exe") && !strings.Contains(lower, ".dll") {
		fmt.Println("Unsupported file type. Expected .exe or .dll")
		usage()
		return
	}

	if err := analyzePE(firstArgument); err != nil {
		fmt.Printf("Analysis error: %v\n", err)
		os.Exit(1)
	}
}
