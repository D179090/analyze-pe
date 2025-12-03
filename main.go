package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	peparser "github.com/saferwall/pe"
)

/*func usage() {
	fmt.Println("Usage: analyzer <option> <file.exe|file.dll>")
	fmt.Println("Example: analyzer -s C:\\Binaries\\notepad.exe")
}*/

func help() {
	fmt.Println("Usage: analyzer <option> <file.exe|file.dll>")
	fmt.Println("Options:")
	fmt.Println("  -h, --help       Show this help message and exit")
	fmt.Println("  -i, --imports    Show imports")
	fmt.Println("  -s, --sections   Show sections")
}

func sectionName(sec peparser.Section) string {
	nameBytes := sec.Header.Name[:]
	n := bytes.IndexByte(nameBytes, 0)
	if n == -1 {
		n = len(nameBytes)
	}
	return string(nameBytes[:n])
}

func sectionsPE(filename string) error {
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
		entropy := sec.CalculateEntropy(f)

		fmt.Printf("Section Name: %s\n", name)
		fmt.Printf("  VirtualSize: 0x%x\n", vsize)
		fmt.Printf("  Characteristics: 0x%x\n", char)
		fmt.Printf("  Entropy: %.3f\n\n", entropy)
	}

	return nil
}

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

	// Проверка количества аргументов
	if len(os.Args) < 3 {
		help()
		os.Exit(1)
	}

	flag := os.Args[1]
	filename := os.Args[2]

	// Проверка расширения файла
	lower := strings.ToLower(filename)
	if !strings.HasSuffix(lower, ".exe") && !strings.HasSuffix(lower, ".dll") {
		fmt.Println("Unsupported file type. Expected .exe or .dll")
		return
	}

	switch flag {

	case "-h", "--help":
		help()
		return

	case "-s", "--sections":
		if err := sectionsPE(filename); err != nil {
			fmt.Printf("Sections extraction error: %v\n", err)
			os.Exit(1)
		}

	case "-i", "--imports":
		if err := importsPE(filename); err != nil {
			fmt.Printf("Imports extraction error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Printf("Unknown option: %s\n", flag)
		help()
	}
}
