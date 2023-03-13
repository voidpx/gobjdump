Utility for dumping ELF executables built with Go
===

This is a simple tool for dumping out some of the information specific to Go from a ELF binary built with Go, such as pc/func data, function argument/local pointer map, etc.

to build:

```bash
$ go build
```

to print usage:

```bash
$ gobjdump -h
```

### Examples

```bash
$ gobjdump mod gobjdump
# moduledata {
#            pcHeader: 0x66cda0
#         funcnametab: 0x66ce00
#               cutab: 0x690380
#             filetab: 0x691020
#               pctab: 0x6952a0
#           pclntable: 0x6db9e0
#                ftab: 0x6db9e0
#         findfunctab: 0x6683c0
#               minpc: 0x401000
#               maxpc: 0x5f3fe6
#                text: 0x401000
#               etext: 0x5f3fe6
#           noptrdata: 0x742500
#          enoptrdata: 0x755740
#                data: 0x755740
# ...
# }

$ gobjdump func gobjdump # print all the functions in gobjdump
$ gobjdump safe -f main.main gobjdump # print the safe points in the function main.main of gobjdump as follows
# main.main(/home/sz/go/gobjdump/main.go):
#     0x5f22a0-->0x5f22ac: safe
#     0x5f22ac-->0x5f22b2: unsafe
#     0x5f22b2-->0x5f22dd: safe
#     0x5f22dd-->0x5f2327: unsafe
#     0x5f2327-->0x5f2339: safe
#     0x5f2339-->0x5f235e: unsafe
#     0x5f235e-->0x5f2374: safe
#     0x5f2374-->0x5f239d: unsafe
#     0x5f239d-->0x5f23b3: safe
# ...

$ gobjdump pcsp -f main.main gobjdump # print the pcsp of the main.main function
# main.main(/home/sz/go/gobjdump/main.go):
#     0x5f22a0-->0x5f22b9: 0x0
#     0x5f22b9-->0x5f3564: 0x238
#     0x5f3564-->0x5f356f: 0x0

   
```