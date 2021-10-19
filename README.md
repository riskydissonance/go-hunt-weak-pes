# Go Hunt Weak PEs

Go binary that finds .EXEs and .DLLs on the system that don't have security controls enabled (ASLR, DEP, CFG etc).


## Usage
```
$ ./go-hunt-weak-pes.exe -path <path1,path2> [-allChecks] [-verbose]
```
By default only PEs without ASLR or DEP are shown, for others add the `-allChecks` flag.
