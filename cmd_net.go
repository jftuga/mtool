package main

import (
	"flag"
	"github.com/jftuga/mtool/internal/netcmd"
	"time"
)

func cmdNet(args []string) error {
	fs := flag.NewFlagSet("net", flag.ExitOnError)
	mode := fs.String("mode", "check", "mode: check, scan, wait, echo")
	timeout := fs.Duration("timeout", 5*time.Second, "connection timeout")
	startPort := fs.Int("start", 1, "start port for scan")
	endPort := fs.Int("end", 1024, "end port for scan")
	addr := fs.String("addr", ":0", "listen address for echo server")
	fs.Parse(args)

	host := ""
	if fs.NArg() > 0 {
		host = fs.Arg(0)
	}

	return netcmd.Run(
		netcmd.WithMode(*mode),
		netcmd.WithTimeout(*timeout),
		netcmd.WithStartPort(*startPort),
		netcmd.WithEndPort(*endPort),
		netcmd.WithAddr(*addr),
		netcmd.WithHost(host),
	)
}
