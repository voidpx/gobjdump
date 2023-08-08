package main

import (
	"os"

	"github.com/voidpx/gobjdump/elf"
	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "gobjdump <command> <file>",
		Short: "ELF dumper for binaries built with Go",
		Long: `gobjdump prints information specific to Go in an ELF executable built with Go. e.g.
* functions and files where they are defined
* pcsp/pcln of functions
* safe points of functions
* local/argument pointer map of functions`,
	}

	var function string

	functionRequried := func(c *cobra.Command) {
		c.Flags().StringVarP(&function, "function", "f", "", "function (required)")
		c.MarkFlagRequired("function")
	}

	requireFile := func(cmd *cobra.Command, args []string) error {
		if err := cobra.MinimumNArgs(1)(cmd, args); err != nil {
			return err
		}
		if _, err := os.Stat(args[0]); err != nil {
			return err
		}
		return nil
	}

	doElfFile := func(f string, fn func(*elf.ELF_Info)) {
		ef := elf.Open(f)
		defer ef.Close()
		fn(ef)
	}

	cmdPrintModule := &cobra.Command{
		Use:   "mod  <file>",
		Short: "print the module data layout",
		Args:  requireFile,
		Run: func(cmd *cobra.Command, args []string) {
			doElfFile(args[0], func(f *elf.ELF_Info) {
				f.PrintModule(os.Stdout)
			})
		},
	}

	cmdPrintFuncs := &cobra.Command{
		Use:   "func <file>",
		Short: "print functions grouped by files where they are defined",
		Args:  requireFile,
		Run: func(cmd *cobra.Command, args []string) {
			doElfFile(args[0], func(f *elf.ELF_Info) {
				f.PrintFuncs(os.Stdout)
			})
		},
	}

	cmdPrintTypes := &cobra.Command{
		Use:   "type <file>",
		Short: "print types that appear in the .typelinks section",
		Args:  requireFile,
		Run: func(cmd *cobra.Command, args []string) {
			doElfFile(args[0], func(f *elf.ELF_Info) {
				f.PrintTypes(os.Stdout)
			})
		},
	}

	cmdPrintPCSP := &cobra.Command{
		Use:   "pcsp <file>",
		Short: "print pc->sp of a function",
		Args:  requireFile,
		Run: func(cmd *cobra.Command, args []string) {
			doElfFile(args[0], func(f *elf.ELF_Info) {
				f.PrintPCSP(os.Stdout, function)
			})

		},
	}
	functionRequried(cmdPrintPCSP)

	cmdPrintPCLN := &cobra.Command{
		Use:   "pcln <file>",
		Short: "print pc->line No. of a function",
		Args:  requireFile,
		Run: func(cmd *cobra.Command, args []string) {
			doElfFile(args[0], func(f *elf.ELF_Info) {
				f.PrintPCLN(os.Stdout, function)
			})

		},
	}
	functionRequried(cmdPrintPCLN)

	cmdPrintSafePoints := &cobra.Command{
		Use:   "safe <file>",
		Short: "print safe points of a function",
		Args:  requireFile,
		Run: func(cmd *cobra.Command, args []string) {
			doElfFile(args[0], func(f *elf.ELF_Info) {
				f.PrintSafePoints(os.Stdout, function)
			})

		},
	}
	functionRequried(cmdPrintSafePoints)

	cmdPrintArgPointerMap := &cobra.Command{
		Use:   "ap <file>",
		Short: "print argument pointer map of a function",
		Args:  requireFile,
		Run: func(cmd *cobra.Command, args []string) {
			doElfFile(args[0], func(f *elf.ELF_Info) {
				f.PrintArgPointerMap(os.Stdout, function)
			})

		},
	}
	functionRequried(cmdPrintArgPointerMap)

	cmdPrintLocalPointerMap := &cobra.Command{
		Use:   "lp <file>",
		Short: "print local pointer map of a function",
		Args:  requireFile,
		Run: func(cmd *cobra.Command, args []string) {
			doElfFile(args[0], func(f *elf.ELF_Info) {
				f.PrintLocalPointerMap(os.Stdout, function)
			})

		},
	}
	functionRequried(cmdPrintLocalPointerMap)

	cmdPrintStackObjs := &cobra.Command{
		Use:   "so <file>",
		Short: "print stack objects of a function",
		Args:  requireFile,
		Run: func(cmd *cobra.Command, args []string) {
			doElfFile(args[0], func(f *elf.ELF_Info) {
				f.PrintStackObjs(os.Stdout, function)
			})

		},
	}

	functionRequried(cmdPrintStackObjs)

	cmd.AddCommand(cmdPrintModule)
	cmd.AddCommand(cmdPrintFuncs)
	cmd.AddCommand(cmdPrintTypes)
	cmd.AddCommand(cmdPrintPCSP)
	cmd.AddCommand(cmdPrintPCLN)
	cmd.AddCommand(cmdPrintSafePoints)
	cmd.AddCommand(cmdPrintArgPointerMap)
	cmd.AddCommand(cmdPrintLocalPointerMap)
	cmd.AddCommand(cmdPrintStackObjs)

	cmd.Execute()
}
