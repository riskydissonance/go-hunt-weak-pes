# Go Hunt Weak PEs

Go binary that finds .EXEs and .DLLs on the system that don't have security controls enabled (ASLR, DEP, CFG etc).


## Usage
```
Usage of go-hunt-weak-pes:
  -allChecks
        Perform checks for SEH, CFG and Integrity Checking in addition to DEP and ASLR
  -dlls
        Only search for DLLs
  -exes
        Only search for EXEs
  -paths string
        The comma separated list of paths to checkPE
  -verbose
        Verbose mode (defaults to false)
```
By default, only PEs without ASLR or DEP are shown, for others add the `-allChecks` flag.
