package elf

import (
	felf "debug/elf"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"
)

const (
	SEC_PCLN      = ".gopclntab"
	SEC_RODATA    = ".rodata"
	FIRST_MOD_SYM = "runtime.firstmoduledata"
)

type ELF_Info struct {
	file         *felf.File
	module       *moduledata
	rodata       []byte
	gofunc       *byte
	pclnLoaded   bool
	rodataLoaded bool
}

func (e *ELF_Info) Close() error {
	return e.file.Close()
}

func (e *ELF_Info) PrintFuncs(out io.Writer) {
	e.loadpcln()
	m := make(map[string][]string)
	for _, f := range e.module.ftab {
		f := (*_func)(unsafe.Pointer(&e.module.pclntable[f.funcoff]))
		e.process_func(out, f, m)
	}

	for k, v := range m {
		fmt.Fprintln(out, k+":")
		for _, fn := range v {
			fmt.Fprintf(out, "    %s\n", fn)
		}
	}
}

func (e *ELF_Info) findFunc(fn string) *_func {
	for _, f := range e.module.ftab {
		f := (*_func)(unsafe.Pointer(&e.module.pclntable[f.funcoff]))
		fname := toString(e.module.funcnametab[f.nameoff:])
		if fname == fn {
			return f
		}
	}
	return nil
}

func (e *ELF_Info) PrintPCSP(out io.Writer, fn string) {
	e.printPCvalue(out, fn,
		func(f *_func) uint32 {
			return f.pcsp
		},
		func(v int) any {
			return v
		})
}

func (e *ELF_Info) loadrodata() {
	if e.rodataLoaded {
		return
	}
	s := e.file.Section(SEC_RODATA)
	if s == nil {
		panic("section not found: " + SEC_RODATA)
	}
	e.rodata = make([]byte, s.Size)
	n, err := s.ReadAt(e.rodata, 0)
	if n < len(e.rodata) {
		panic(err)
	}
	d := e.module.gofunc - e.module.rodata
	e.gofunc = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&e.rodata[0])) + d))
	e.rodataLoaded = true
}

func (e *ELF_Info) PrintLocalPointerMap(out io.Writer, fn string) {
	e.printPointerMap(out, fn, _FUNCDATA_LocalsPointerMaps)
}

func (e *ELF_Info) PrintArgPointerMap(out io.Writer, fn string) {
	e.printPointerMap(out, fn, _FUNCDATA_ArgsPointerMaps)
}

func (e *ELF_Info) printPointerMap(out io.Writer, fn string, i uint8) {
	e.loadpcln()
	f := e.findFunc(fn)
	if f == nil {
		fmt.Fprintln(os.Stderr, "function not found: "+fn)
		os.Exit(1)
	}
	e.printFuncNameAndFile(out, f, fn)
	p, off := e.funcdata(f, i)
	fmt.Fprintf(out, "%#x:\n", off)
	m := (*stackmap)(p)
	printstackmap(out, m)
}

func printstackmap(out io.Writer, m *stackmap) {
	for i := 0; i < int(m.n); i++ {
		b := (m.nbit + 7) / 8
		bytes := uintptr(unsafe.Pointer(&m.bytedata[0])) + uintptr(i*int(b))
		s := make([]string, b)
		for j := 0; j < int(b); j++ {
			s[j] = fmt.Sprintf("%8.8b", *(*byte)(unsafe.Pointer(bytes + uintptr(j))))
		}
		fmt.Fprintln(out, "  "+strings.Join(s, " "))
	}
}

func (e *ELF_Info) funcdata(f *_func, i uint8) (unsafe.Pointer, uintptr) {
	e.loadrodata()
	p := uintptr(unsafe.Pointer(&f.nfuncdata)) + unsafe.Sizeof(f.nfuncdata) + uintptr(f.npcdata)*4 + uintptr(i)*4
	off := *(*uint32)(unsafe.Pointer(p))
	if off == ^uint32(0) {
		return unsafe.Pointer(uintptr(0)), 0
	}
	return unsafe.Pointer(uintptr(unsafe.Pointer(e.gofunc)) + uintptr(off)), e.module.gofunc + uintptr(off)
}

func (e *ELF_Info) printFuncNameAndFile(out io.Writer, f *_func, fn string) {
	fmt.Fprintln(out, fn+"("+e.func_file(f)+"):")
}

func (e *ELF_Info) printPCvalue(out io.Writer, fn string, of func(*_func) uint32,
	vm func(int) any) {
	e.loadpcln()
	f := e.findFunc(fn)
	if f == nil {
		fmt.Fprintf(out, "function '%s' not found", fn)
		os.Exit(1)
	}
	e.printFuncNameAndFile(out, f, fn)
	p := e.module.pctab[of(f):]
	first := true
	entry := e.module.text + uintptr(f.entryoff)
	pcstart := entry
	d := -1
	for r, vd, pd := pc_next(p, first); r != nil; r, vd, pd = pc_next(p, first) {
		if first {
			first = false
		}
		pc := pcstart + uintptr(pd)
		d += int(vd)
		m := vm(d)
		switch tv := m.(type) {
		case uint8, uint16, uint32, uint64, int8, int16, int32, int64, int, uintptr:
			fmt.Fprintf(out, "    %#x-->%#x: %#x\n", pcstart, pc, tv)
		case string:
			fmt.Fprintf(out, "    %#x-->%#x: %s\n", pcstart, pc, tv)
		default:
			fmt.Fprintf(out, "    %#x-->%#x: %v\n", pcstart, pc, tv)
		}
		p = r
		pcstart = pc
	}
}

func (e *ELF_Info) PrintUnsafePoints(out io.Writer, fn string) {
	e.printPCvalue(out, fn,
		func(f *_func) uint32 {
			return *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&f.nfuncdata)) + unsafe.Sizeof(f.nfuncdata))) // + _PCDATA_UnsafePoint*4
		},
		func(v int) any {
			switch v {
			case _PCDATA_UnsafePointSafe:
				return "safe"
			case _PCDATA_UnsafePointUnsafe:
				return "unsafe"
			case _PCDATA_Restart1:
				return "restart1"
			case _PCDATA_Restart2:
				return "restart2"
			case _PCDATA_RestartAtEntry:
				return "restartAtEntry"
			default:
				return v
			}
		})
}

func (e *ELF_Info) PrintModule(out io.Writer) {
	printModule(out, e.module)
}

func (e *ELF_Info) getFuncName(f *_func) string {
	return toString(e.module.funcnametab[f.nameoff:])
}

func (e *ELF_Info) process_func(out io.Writer, fn *_func, m map[string][]string) {
	fname := e.getFuncName(fn)
	file := e.func_file(fn)
	if s, ok := m[file]; ok {
		m[file] = append(s, fname)
	} else {
		m[file] = []string{fname}
	}
}

func (e *ELF_Info) func_file(fn *_func) string {
	_, fileno := readvarint(e.module.pctab[fn.pcfile:])
	fileno = uint32(zigzag_decode(fileno)) - 1 // pc delta starts at -1
	if fn.cuOffset != ^uint32(0) && int(fn.cuOffset+fileno) < len(e.module.cutab) {
		if fileoff := e.module.cutab[fn.cuOffset+fileno]; fileoff != ^uint32(0) {
			if int(fileoff) < len(e.module.filetab) {
				return toString(e.module.filetab[fileoff:])
			}
		}
	}
	return "?"
}

func pc_next(p []byte, first bool) (r []byte, vdelta int32, pcdelta int32) {
	n, v := readvarint(p)
	vdelta = zigzag_decode(v)
	if vdelta == 0 && !first {
		return nil, 0, 0
	}
	p = p[n:]
	n, pd := readvarint(p)
	pcdelta = int32(pd)
	r = p[n:]
	return
}

func readvarint(p []byte) (read uint32, val uint32) {
	var v, shift, n uint32
	for {
		b := p[n]
		n++
		v |= uint32(b&0x7F) << (shift & 31)
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return n, v
}

func zigzag_decode(d uint32) int32 {
	return int32(-(d & 1) ^ (d >> 1))
}

func toString(fnames []byte) string {
	type str struct {
		p unsafe.Pointer
		l uint64
	}
	l := indexByte(fnames, 0)
	if l < 0 {
		l = 0
	}
	s := unsafe.Pointer(&str{unsafe.Pointer(&fnames[0]), uint64(l)})
	return *(*string)(s)
}

func indexByte(bytes []byte, b byte) int {
	for i, e := range bytes {
		if e == b {
			return i
		}
	}
	return -1
}

func Open(elf string) *ELF_Info {
	f, e := felf.Open(elf)
	if e != nil {
		panic(e)
	}

	syms, e := f.Symbols()
	if e != nil {
		panic(e)
	}
	var fms *felf.Symbol
	for _, sym := range syms {
		if sym.Name == FIRST_MOD_SYM {
			fms = &sym
			break
		}
	}
	if fms == nil || fms.Section <= 0 {
		panic("symbol not found: " + FIRST_MOD_SYM)
	}
	var gosec *felf.Section = f.Sections[fms.Section]
	off := fms.Value - gosec.Addr

	mds := unsafe.Sizeof(moduledata{})
	var b = make([]byte, mds)
	n, e := gosec.ReadAt(b, int64(off))
	if n < len(b) {
		panic(e)
	}

	m := (*moduledata)(unsafe.Pointer(&b[0]))
	ei := &ELF_Info{file: f, module: m}
	return ei
}

func (e *ELF_Info) loadpcln() {
	if e.pclnLoaded {
		return
	}
	pcln := e.file.Section(SEC_PCLN)
	if pcln == nil {
		panic("section not found: " + SEC_PCLN)
	}
	b := make([]byte, pcln.Size)
	n, err := pcln.ReadAt(b, 0)
	if n < len(b) {
		panic(err)
	}
	delta := int64(uintptr(unsafe.Pointer(&b[0]))) - int64(uintptr(unsafe.Pointer(e.module.pcHeader)))
	relocate_module(e.module, delta)
	e.pclnLoaded = true
}

func relocate_module(m *moduledata, d int64) {
	relocate(unsafe.Pointer(&m.pcHeader), d)
	relocate(unsafe.Pointer(&m.funcnametab), d)
	relocate(unsafe.Pointer(&m.cutab), d)
	relocate(unsafe.Pointer(&m.filetab), d)
	relocate(unsafe.Pointer(&m.pctab), d)
	relocate(unsafe.Pointer(&m.pclntable), d)
	relocate(unsafe.Pointer(&m.ftab), d)
}

func relocate(p unsafe.Pointer, delta int64) {
	*(*uintptr)(p) = uintptr(*(*int64)(p) + delta)
}
