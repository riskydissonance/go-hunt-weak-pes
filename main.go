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
			walkDirectory(&path, config.allChecks, config.verbose, config.justExes, config.justDlls)
		}
	} else {
		walkDirectory(&config.paths, config.allChecks, config.verbose, config.justExes, config.justDlls)
	}
}

func walkDirectory(pPath *string, allChecks bool, verbose bool, justExes bool, justDlls bool) {
	err := filepath.Walk(*pPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if verbose {
				fmt.Println(err)
			}
			return nil
		}
		if (!justDlls && strings.EqualFold(filepath.Ext(path), ".exe")) ||
			(!justExes && strings.EqualFold(filepath.Ext(path), ".dll")) {
			checkPE(path, allChecks, verbose)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
}

func checkPE(name string, allChecks bool, verbose bool) {

	if verbose {
		fmt.Printf("[*] Checking: %s\n", name)
	}

	var (
		noNx              bool
		noAslr            bool
		noSeh             bool
		noCfg             bool
		noIntegrityChecks bool
		is64bit           bool

		optionalHeader32 pe.OptionalHeader32
		optionalHeader64 pe.OptionalHeader64
	)

	ioFile, err := os.Open(name)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Could not open peFile for reading: %s - %s\n", name, err)
		}
		return
	}

	base, err := getBase(ioFile)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Could not read Image Header: %s\n", err)
		}
		return
	}

	peFile, err := pe.Open(name)
	if err != nil {
		return
	}

	sectionReader := io.NewSectionReader(ioFile, 0, 1<<63-1)
	err = readFileHeader(sectionReader, base, peFile)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Could read Image File Header: %s\n", err)
		}
		return
	}

	is64bit, err = readImageOptionalHeader(peFile, sectionReader, &optionalHeader32, &optionalHeader64)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Could not read Image Optional Header: %s\n", err)
		}
		return
	}

	if is64bit {
		noNx, noAslr, noSeh, noCfg, noIntegrityChecks = checkCharacteristics(optionalHeader64.DllCharacteristics)
	} else {
		noNx, noAslr, noSeh, noCfg, noIntegrityChecks = checkCharacteristics(optionalHeader32.DllCharacteristics)
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

func checkCharacteristics(dllCharacteristics uint16) (bool, bool, bool, bool, bool) {
	var (
		noNx              bool
		noAslr            bool
		noSeh             bool
		noCfg             bool
		noIntegrityChecks bool
	)
	if dllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT == 0 {
		noNx = true
	}
	if dllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0 {
		noAslr = true
	}
	if dllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
		noSeh = true
	}
	if dllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF == 0 {
		noCfg = true
	}
	if dllCharacteristics&pe.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY == 0 {
		noIntegrityChecks = true
	}
	return noNx, noAslr, noSeh, noCfg, noIntegrityChecks
}

func readImageOptionalHeader(peFile *pe.File, sectionReader *io.SectionReader, optionalHeader32 *pe.OptionalHeader32, optionalHeader64 *pe.OptionalHeader64) (bool, error) {
	var (
		sizeofOptionalHeader32 = uint16(binary.Size(pe.OptionalHeader32{}))
		sizeofOptionalHeader64 = uint16(binary.Size(pe.OptionalHeader64{}))
	)

	switch peFile.FileHeader.SizeOfOptionalHeader {
	case sizeofOptionalHeader32:
		err := binary.Read(sectionReader, binary.LittleEndian, optionalHeader32)
		if err != nil {
			return false, err
		}
		if optionalHeader32.Magic != 0x10b {
			return false, fmt.Errorf("unexpected magic byte: %d", optionalHeader32.Magic)
		}
		return false, nil

	case sizeofOptionalHeader64:
		err := binary.Read(sectionReader, binary.LittleEndian, optionalHeader64)
		if err != nil {
			return false, err
		}
		if optionalHeader64.Magic != 0x20b {
			return false, fmt.Errorf("unexpected magic byte: %d", optionalHeader64.Magic)
		}
		return true, nil
	default:
		return false, fmt.Errorf("unexpected optional header size: %d", peFile.FileHeader.SizeOfOptionalHeader)
	}

}

func readFileHeader(sectionReader *io.SectionReader, base int64, peFile *pe.File) error {
	_, err := sectionReader.Seek(base, io.SeekStart)
	if err != nil {
		return err
	}
	err = binary.Read(sectionReader, binary.LittleEndian, &peFile.FileHeader)
	if err != nil {
		return err
	}
	return nil
}

func getBase(ioFile *os.File) (int64, error) {
	var dosHeader [96]byte
	var sign [4]byte
	_, err := ioFile.ReadAt(dosHeader[0:], 0)
	if err != nil {
		return 0, err
	}
	var base int64
	if dosHeader[0] == 'M' && dosHeader[1] == 'Z' {
		signOff := int64(binary.LittleEndian.Uint32(dosHeader[0x3c:]))
		_, err := ioFile.ReadAt(sign[:], signOff)
		if err != nil {
			return 0, err
		}
		if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) {
		}
		base = signOff + 4
	} else {
		base = int64(0)
	}
	return base, nil
}

type config struct {
	paths     string
	allChecks bool
	verbose   bool
	justExes  bool
	justDlls  bool
}

func getConfig() config {

	flags := flag.NewFlagSet("go-hunt-weak-pes", flag.ExitOnError)

	pPaths := flags.String("paths", "", "The comma separated list of paths to checkPE")
	pAllChecks := flags.Bool("allChecks", false, "Perform checks for SEH, CFG and Integrity Checking in addition to DEP and ASLR")
	pVerbose := flags.Bool("verbose", false, "Verbose mode (defaults to false)")
	pJustExes := flags.Bool("exes", false, "Only search for EXEs")
	pJustDlls := flags.Bool("dlls", false, "Only search for DLLs")

	err := flags.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	if *pPaths == "" {
		fmt.Println("Usage: ")
		flags.PrintDefaults()
		os.Exit(1)
	}

	if *pJustExes && *pJustDlls {
		fmt.Println("-exes and -dlls cannot both be set at the same time")
		fmt.Println("Usage: ")
		flags.PrintDefaults()
		os.Exit(1)
	}

	return config{paths: *pPaths, allChecks: *pAllChecks, verbose: *pVerbose, justExes: *pJustExes, justDlls: *pJustDlls}
}
