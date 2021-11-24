package main

import (
	"flag"
	"os"

	"antrea.io/antrea/pkg/log"
	"antrea.io/antrea/pkg/version"
	"github.com/spf13/cobra"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	command := newAgentTweakerCommand()
	if err := command.Execute(); err != nil {
		logs.FlushLogs()
		os.Exit(1)
	}
}

func newAgentTweakerCommand() *cobra.Command {
	opts := newOptions()

	cmd := &cobra.Command{
		Use:  "antrea-agent-tweaker",
		Long: "Tweak antrea agent behaviours before it start",
		Run: func(cmd *cobra.Command, args []string) {
			log.InitLogs(cmd.Flags())
			if err := opts.complete(args); err != nil {
				klog.Fatalf("Failed to complete: %v", err)
			}
			if err := opts.validate(args); err != nil {
				klog.Fatalf("Failed to validate: %v", err)
			}
			if err := run(opts); err != nil {
				klog.Fatalf("Error running agent: %v", err)
			}
		},
		Version: version.GetFullVersionWithRuntimeInfo(),
	}

	flags := cmd.Flags()
	opts.addFlags(flags)
	log.AddFlags(flags)
	// Install log flags
	flags.AddGoFlagSet(flag.CommandLine)
	return cmd
}
