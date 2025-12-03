package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	peparser "github.com/saferwall/pe"
)

func usage() {
	fmt.Println("Usage: analyzer <file.exe|file.dll>")
	fmt.Println("Example: analyzer C:\\Binaries\\notepad.exe")
}

func help() {
	fmt.Println("Usage: analyzer <file.exe|file.dll>")
	fmt.Println("Example: analyzer C:\\Binaries\\notepad.exe")
	fmt.Println("Options:")
	fmt.Println("  -h, --help    Show this help message and exit")
	fmt.Println("  -i, --imports Show imports")
	fmt.Println("  -s, --sections Show sections")
}

func sectionName(sec peparser.Section) string {
	nameBytes := sec.Header.Name[:]
	n := bytes.IndexByte(nameBytes, 0)
	if n == -1 {
		n = len(nameBytes)
	}
	return string(nameBytes[:n])
}

// analyzePE открывает и парсит PE-файл и выводит простую информацию о секциях.
func analyzePE(filename string) error {
	f, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}

	if err := f.Parse(); err != nil {
		return fmt.Errorf("error parsing PE: %w", err)
	}

	fmt.Printf("Successfully parsed %s\n", filename)
	fmt.Printf("Number of sections: %d\n", len(f.Sections))

	for _, sec := range f.Sections {
		name := sectionName(sec)
		vsize := sec.Header.VirtualSize
		char := sec.Header.Characteristics
		entropy := sec.CalculateEntropy(f) // согласно документации

		fmt.Printf("Section Name: %s\n", name)
		fmt.Printf("  VirtualSize: 0x%x\n", vsize)
		fmt.Printf("  Characteristics: 0x%x\n", char)
		fmt.Printf("  Entropy: %.3f\n\n", entropy)
	}

	return nil
}

// importsPE выводит таблицу импортов.
func importsPE(filename string) error {
	f, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}

	if err := f.Parse(); err != nil {
		return fmt.Errorf("error parsing PE: %w", err)
	}

	if len(f.Imports) == 0 {
		log.Printf("No imports found in %s\n", filename)
		return nil
	}

	for _, imp := range f.Imports {
		log.Printf("DLL: %s", imp.Name)
		for _, e := range imp.Functions {
			if e.Name != "" {
				log.Printf("  -> %s", e.Name)
			} else {
				log.Printf("  -> ord: %d", e.Ordinal)
			}
		}
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
		help()
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

	if firstArgument == "imports" || firstArgument == "--imports" || firstArgument == "-i" {
		if err := importsPE(firstArgument); err != nil {
			fmt.Printf("Imports extraction error: %v\n", err)
			os.Exit(1)
		}
	}

	if firstArgument == "sections" || firstArgument == "--sections" || firstArgument == "-s" {
		if err := sectionsPE(firstArgument); err != nil {
			fmt.Printf("Sections extraction error: %v\n", err)
			os.Exit(1)
		}
	}
}
