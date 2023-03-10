package main

import (
	"os"

	"github.com/sam-zheng/gobjdump/elf"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func main() {
	cmd := &cobra.Command{
		Use:   "gobjdump [options] <elf file>",
		Short: "ELF dumper for binaries built with Go",
		Long: `gobjdump prints information included in the ELF file. e.g.
* functions and files where they are contained
* pcsp of functions
* unsafe points of functions
* local/argument pointer map`,
		Run: func(cmd *cobra.Command, args []string) {
			fun := cmd.Flag("function").Value.String()
			print(fun)
			f := elf.Open(args[0])
			defer f.Close()
			//f.PrintFuncs(os.Stdout)
			// f.PrintModule(os.Stdout)
			// f.PrintUnsafePoints(os.Stdout, "main.main")
			f.PrintLocalPointerMap(os.Stdout, "main.main")
		},
	}
	cmd.Flags().AddFlag(&pflag.Flag{Name: "function", Shorthand: "f"})
	cmd.Execute()
}
