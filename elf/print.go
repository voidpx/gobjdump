package elf

import (
	"fmt"
	"io"
	"reflect"
	"unsafe"
)

type eface struct {
	t unsafe.Pointer
	d unsafe.Pointer
}

func printModule(out io.Writer, m *moduledata) {
	printObject(out, m, 0, 1)
}

// printObject prints the object o, only dereferences pointers if level <= limit
// this is to not dereference pointers that may still have invalid address, i.e. not relocated properly yet
func printObject(out io.Writer, o any, level int, limit int) {
	level++
	follow_pointer := level <= limit
	t := reflect.TypeOf(o)
	v := reflect.ValueOf(o)
	switch t.Kind() {
	case reflect.Uintptr, reflect.UnsafePointer:
		fmt.Fprintf(out, "0x%x", *(*uintptr)(unsafe.Pointer(((*eface)(unsafe.Pointer(&o)).d))))
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprintf(out, "%d", o)
	case reflect.Slice, reflect.String: // print the address of the backing storage
		printObject(out, (*reflect.StringHeader)((*eface)(unsafe.Pointer(&o)).d).Data, level, limit)
	case reflect.Pointer:
		if follow_pointer {
			ev := v.Elem()
			if ev.CanInterface() {
				printObject(out, ev.Interface(), level, limit)
			} else {
				printObject(out, getValue(ev, follow_pointer), level, limit)
			}
		} else {
			printObject(out, v.Pointer(), level, limit)
		}
	case reflect.Struct:
		fmt.Fprintln(out, t.Name()+" {")
		for i := 0; i < t.NumField(); i++ {
			fmt.Fprint(out, "    ")
			fmt.Fprintf(out, "%15s", t.Field(i).Name)
			fmt.Fprint(out, ": ")
			ev := v.Field(i)
			if ev.CanInterface() {
				printObject(out, ev.Interface(), level, limit)
			} else {
				printObject(out, getValue(ev, follow_pointer), level, limit)
			}
			fmt.Fprintln(out)
		}
		fmt.Fprintln(out, "}")
	default:
		fmt.Fprint(out, o)
	}
}

func getValue(v reflect.Value, follow_pointer bool) any {
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint()
	case reflect.Float32, reflect.Float64:
		return v.Float()
	case reflect.Complex64, reflect.Complex128:
		return v.Complex()
	case reflect.Interface:
		getValue(v.Elem(), follow_pointer)
	case reflect.Pointer:
		if follow_pointer {
			return getValue(v.Elem(), follow_pointer)
		} else {
			return v.Pointer()
		}
	case reflect.Uintptr:
		return uintptr(v.Uint())
	case reflect.String:
		if v.CanAddr() {
			return *(*uintptr)(v.Addr().UnsafePointer())
		} else {
			return "?"
		}
	case reflect.Array:
		//
	case reflect.Map, reflect.Chan,
		reflect.Func, reflect.Slice, reflect.UnsafePointer:
		return v.Pointer()
	}
	if v.CanAddr() {
		return v.Addr().UnsafePointer()
	}
	return "?"
}
