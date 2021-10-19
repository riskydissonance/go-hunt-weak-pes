package main

import (
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	config := getConfig()
	if strings.Contains(config.paths, ",") {
		for _, path := range strings.Split(config.paths, ",") {
			walkDirectory(&path, config.allChecks, config.verbose)
		}
	} else {
		walkDirectory(&config.paths, config.allChecks, config.verbose)
	}
}

func walkDirectory(path *string, allChecks bool, verbose bool) {
	err := filepath.Walk(*path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return nil
		}
		if filepath.Ext(path) == ".exe" || filepath.Ext(path) == ".dll" {
			check(path, allChecks, verbose)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
}

func check(name string, allChecks bool, verbose bool) {
	if verbose {
		fmt.Printf("[*] Checking: %s\n", name)
	}
	file, err := pe.Open(name)
	if err != nil {
		return
	}
	var noNx bool
	var noAslr bool
	var noSeh bool
	var noCfg bool
	var noIntegrityChecks bool
	var is64bit bool

	var sizeofOptionalHeader32 = uint16(binary.Size(pe.OptionalHeader32{}))
	var sizeofOptionalHeader64 = uint16(binary.Size(pe.OptionalHeader64{}))
	var optionalHeader32 pe.OptionalHeader32
	var optionalHeader64 pe.OptionalHeader64

	ioFile, err := os.Open(name)
	if err != nil {
		fmt.Printf("[-] Could not open file for reading:%s - %s\n", name, err)
		return
	}
	var dosHeader [96]byte
	var sign [4]byte
	_, err = ioFile.ReadAt(dosHeader[0:], 0)
	if err != nil {
		fmt.Printf("[-] Could not read Image Header: %s\n", err)
		return
	}
	var base int64
	if dosHeader[0] == 'M' && dosHeader[1] == 'Z' {
		signOff := int64(binary.LittleEndian.Uint32(dosHeader[0x3c:]))
		_, err := ioFile.ReadAt(sign[:], signOff)
		if err != nil {
			fmt.Printf("[-] Could not read Image Header: %s\n", err)
			return
		}
		if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) {
			fmt.Printf("Invalid PE File Format.\n")
		}
		base = signOff + 4
	} else {
		base = int64(0)
	}
	sr := io.NewSectionReader(ioFile, 0, 1<<63-1)
	_, err = sr.Seek(base, os.SEEK_SET)
	if err != nil {
		fmt.Printf("[-] Could not seek in file: %s\n", err)
		return
	}
	err = binary.Read(sr, binary.LittleEndian, &file.FileHeader)
	if err != nil {
		fmt.Printf("[-] Could not read Image Header: %s\n", err)
		return
	}
	switch file.FileHeader.SizeOfOptionalHeader {
	case sizeofOptionalHeader32:
		err := binary.Read(sr, binary.LittleEndian, &optionalHeader32)
		if err != nil {
			fmt.Printf("[-] Could not read Image Optional Header: %s\n", err)
			return
		}
		if optionalHeader32.Magic != 0x10b { // PE32
			fmt.Printf("[-] pe32 optional header has unexpected Magic of 0x%x\n", optionalHeader32.Magic)
			return
		}
		is64bit = false

	case sizeofOptionalHeader64:
		err := binary.Read(sr, binary.LittleEndian, &optionalHeader64)
		if err != nil {
			fmt.Printf("[-] Could not read Image Optional Header: %s\n", err)
			return
		}
		if optionalHeader64.Magic != 0x20b { // PE32+
			fmt.Printf("[-] pe32+ optional header has unexpected Magic of 0x%x\n", optionalHeader64.Magic)
			return
		}
		is64bit = true
	}

	if is64bit {
		if optionalHeader64.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT == 0 {
			noNx = true
		}
		if optionalHeader64.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0 {
			noAslr = true
		}
		if optionalHeader64.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
			noSeh = true
		}
		if optionalHeader64.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF == 0 {
			noCfg = true
		}
		if optionalHeader64.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY == 0 {
			noIntegrityChecks = true
		}
	} else {
		if optionalHeader32.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT == 0 {
			noNx = true
		}
		if optionalHeader32.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0 {
			noAslr = true
		}
		if optionalHeader32.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
			noSeh = true
		}
		if optionalHeader32.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF == 0 {
			noCfg = true
		}
		if optionalHeader32.DllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY == 0 {
			noIntegrityChecks = true
		}
	}
	if noNx {
		fmt.Printf("[+] [No NX] %s\n", name)
	}
	if noAslr {
		fmt.Printf("[+] [No ASLR] %s\n", name)
	}
	if allChecks {
		if noSeh {
			fmt.Printf("[+] [No SEH] %s\n", name)
		}
		if noCfg {
			fmt.Printf("[+] [No CFG] %s\n", name)
		}
		if noIntegrityChecks {
			fmt.Printf("[+] [No Itegrity Checks] %s\n", name)
		}
	}

}

type config struct {
	paths     string
	allChecks bool
	verbose   bool
}

func getConfig() config {

	flags := flag.NewFlagSet("go-hunt-weak-pes", flag.ExitOnError)

	paths := flags.String("paths", "", "The comma separated list of paths to check")
	allChecks := flags.Bool("allChecks", false, "Perform checks for canaries and retguard in addition to DEP and ASLR")
	verbose := flags.Bool("verbose", false, "Verbose mode (defaults to false)")

	err := flags.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	if *paths == "" {
		fmt.Println("Usage: ")
		flags.PrintDefaults()
		os.Exit(1)
	}

	return config{paths: *paths, allChecks: *allChecks, verbose: *verbose}
}
