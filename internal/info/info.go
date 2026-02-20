package info

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"maps"
	"github.com/jftuga/mtool/v2/internal/shared"
	"net"
	"net/netip"
	"os"
	"os/user"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// SystemInfo holds system information data.
type SystemInfo struct {
	XMLName   xml.Name          `xml:"system" json:"-"`
	Hostname  string            `xml:"hostname" json:"hostname"`
	Username  string            `xml:"username" json:"username"`
	HomeDir   string            `xml:"home_dir" json:"home_dir"`
	OS        string            `xml:"os" json:"os"`
	Arch      string            `xml:"arch" json:"arch"`
	CPUs      int               `xml:"cpus" json:"cpus"`
	GoVersion string            `xml:"go_version" json:"go_version"`
	PID       int               `xml:"pid" json:"pid"`
	UID       int               `xml:"uid" json:"uid"`
	WorkDir   string            `xml:"work_dir" json:"work_dir"`
	TempDir   string            `xml:"temp_dir" json:"temp_dir"`
	Time      string            `xml:"time" json:"time"`
	Uptime    string            `xml:"uptime" json:"uptime,omitempty"`
	MemAlloc  string            `xml:"mem_alloc" json:"mem_alloc"`
	Network   []NetworkInfo     `xml:"network>interface" json:"network"`
	Env       map[string]string `xml:"env,omitempty" json:"env,omitempty"`
}

// NetworkInfo holds network interface information.
type NetworkInfo struct {
	Name  string   `xml:"name" json:"name"`
	Addrs []string `xml:"addr" json:"addrs"`
}

// Config holds configuration for the info command.
type Config struct {
	Format  string
	ShowEnv bool
}

// Option configures a Config.
type Option func(*Config)

func WithFormat(format string) Option { return func(c *Config) { c.Format = format } }
func WithShowEnv(showEnv bool) Option { return func(c *Config) { c.ShowEnv = showEnv } }

// Run displays system information.
func Run(opts ...Option) error {
	cfg := &Config{Format: "table"}
	for _, o := range opts {
		o(cfg)
	}

	hostname, _ := os.Hostname()
	wd, _ := os.Getwd()

	var username, homeDir string
	if u, err := user.Current(); err == nil {
		username = u.Username
		homeDir = u.HomeDir
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	info := SystemInfo{
		Hostname:  hostname,
		Username:  username,
		HomeDir:   homeDir,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		CPUs:      runtime.NumCPU(),
		GoVersion: runtime.Version(),
		PID:       os.Getpid(),
		UID:       os.Getuid(),
		WorkDir:   wd,
		TempDir:   os.TempDir(),
		Time:      time.Now().Format(time.RFC3339),
		MemAlloc:  shared.FormatSize(int64(memStats.Alloc)),
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}
			ni := NetworkInfo{Name: iface.Name}
			for _, a := range addrs {
				addrStr := a.String()
				prefix, err := netip.ParsePrefix(addrStr)
				if err == nil {
					ni.Addrs = append(ni.Addrs, prefix.String())
				} else {
					ni.Addrs = append(ni.Addrs, addrStr)
				}
			}
			info.Network = append(info.Network, ni)
		}
	}

	if cfg.ShowEnv {
		info.Env = make(map[string]string)
		for _, e := range os.Environ() {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				info.Env[parts[0]] = parts[1]
			}
		}
	}

	switch cfg.Format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	case "xml":
		enc := xml.NewEncoder(os.Stdout)
		enc.Indent("", "  ")
		if err := enc.Encode(info); err != nil {
			return err
		}
		fmt.Println()
		return nil
	case "csv":
		w := csv.NewWriter(os.Stdout)
		rv := reflect.ValueOf(info)
		rt := rv.Type()
		for i := range rt.NumField() {
			f := rt.Field(i)
			if f.Name == "XMLName" || f.Name == "Network" || f.Name == "Env" {
				continue
			}
			val := fmt.Sprintf("%v", rv.Field(i).Interface())
			w.Write([]string{f.Name, val})
		}
		if len(info.Env) > 0 {
			keys := slices.Sorted(maps.Keys(info.Env))
			for _, k := range keys {
				w.Write([]string{k, info.Env[k]})
			}
		}
		w.Flush()
		return w.Error()
	default: // table
		tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintf(tw, "Hostname:\t%s\n", info.Hostname)
		fmt.Fprintf(tw, "Username:\t%s\n", info.Username)
		fmt.Fprintf(tw, "Home Dir:\t%s\n", info.HomeDir)
		fmt.Fprintf(tw, "OS/Arch:\t%s/%s\n", info.OS, info.Arch)
		fmt.Fprintf(tw, "CPUs:\t%d\n", info.CPUs)
		fmt.Fprintf(tw, "Go Version:\t%s\n", info.GoVersion)
		fmt.Fprintf(tw, "PID:\t%d\n", info.PID)
		fmt.Fprintf(tw, "UID:\t%d\n", info.UID)
		fmt.Fprintf(tw, "Work Dir:\t%s\n", info.WorkDir)
		fmt.Fprintf(tw, "Temp Dir:\t%s\n", info.TempDir)
		fmt.Fprintf(tw, "Time:\t%s\n", info.Time)
		fmt.Fprintf(tw, "Memory:\t%s\n", info.MemAlloc)
		for _, ni := range info.Network {
			fmt.Fprintf(tw, "Net %s:\t%s\n", ni.Name, strings.Join(ni.Addrs, ", "))
		}
		if len(info.Env) > 0 {
			fmt.Fprintf(tw, "\nEnvironment:\n")
			keys := slices.Sorted(maps.Keys(info.Env))
			for _, k := range keys {
				fmt.Fprintf(tw, "  %s\t%s\n", k, info.Env[k])
			}
		}
		return tw.Flush()
	}
}
