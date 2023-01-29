package goss

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// UserEnts represents a hashmap of UserEnt as key is the inode.
type UserEnts map[uint32]*UserEnt

// ResolveAddr lookup first hostname from IP Address.
func ResolveAddr(addr string) string {
	hostnames, _ := net.LookupAddr(addr)
	if len(hostnames) > 0 {
		return strings.TrimSuffix(hostnames[0], ".")
	}
	return addr
}

// LocalIPAddrs gets the string slice of localhost IPaddrs.
func LocalIPAddrs() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, errors.New("failed to get local addresses:" + err.Error())
	}
	addrStrings := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				addrStrings = append(addrStrings, ipnet.IP.String())
			}
		}
	}
	return addrStrings, nil
}

// IsPrivateIP returns whether 'ip' is in private network space.
func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// BuildUserEntries scans under /proc/%pid/FD/.
func BuildUserEntries() (UserEnts, error) {
	root := os.Getenv("PROC_ROOT")
	if root == "" {
		root = "/proc"
	}
	dir, err := ioutil.ReadDir(root)
	if err != nil {
		return nil, err
	}

	userEnts := make(UserEnts, 0)
	for _, d := range dir {
		// find only "<pid>"" directory
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}

		// skip self process
		if pid == os.Getpid() {
			continue
		}

		pidDir := filepath.Join(root, d.Name())
		fdDir := filepath.Join(pidDir, "fd")

		// exists FD?
		fi, err := os.Stat(fdDir)
		switch {
		case err != nil:
			return nil, fmt.Errorf("stat %s: %v", fdDir, err)
		case !fi.IsDir():
			continue
		}

		dir2, err := ioutil.ReadDir(fdDir)
		if err != nil {
			pathErr := err.(*os.PathError)
			errno := pathErr.Err.(syscall.Errno)
			if errno == syscall.EACCES {
				// ignore "open: <path> permission denied"
				continue
			}
			return nil, fmt.Errorf("readdir %s: %v", errno, err)
		}

		var stat *procStat

		for _, d2 := range dir2 {
			fd, err := strconv.Atoi(d2.Name())
			if err != nil {
				continue
			}
			fdpath := filepath.Join(fdDir, d2.Name())
			lnk, err := os.Readlink(fdpath)
			if err != nil {
				pathErr := err.(*os.PathError)
				errno := pathErr.Err.(syscall.Errno)
				if errno == syscall.ENOENT {
					// ignore "readlink: no such file or directory"
					// because fdpath is disappear depending on timing
					log.Printf("%v\n", pathErr)
					continue
				}
				return nil, fmt.Errorf("readlink %s: %v", fdpath, err)
			}
			ino, err := parseSocketInode(lnk)
			if err != nil {
				return nil, err
			}
			if ino == 0 {
				continue
			}

			if stat == nil {
				stat, err = parseProcStat(root, pid)
				if err != nil {
					return nil, err
				}
			}

			userEnts[ino] = &UserEnt{
				Inode: ino,
				FD:    fd,
				Pid:   pid,
				PName: stat.Pname,
				PPid:  stat.Ppid,
				PGid:  stat.Pgrp,
			}
		}
	}
	return userEnts, nil
}

type procStat struct {
	Pname string // process name
	Ppid  int    // parent process id
	Pgrp  int    // process group id
}

func parseProcStat(root string, pid int) (*procStat, error) {
	stat := fmt.Sprintf("%s/%d/stat", root, pid)
	f, err := os.Open(stat)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", stat, err)
	}
	defer f.Close()

	var (
		pid2  int
		comm  string
		state string
		ppid  int
		pgrp  int
	)
	if _, err := fmt.Fscan(f, &pid2, &comm, &state, &ppid, &pgrp); err != nil {
		return nil, fmt.Errorf("could not scan '%s': %w", stat, err)
	}

	var pname string
	// workaround: Sscanf return io.ErrUnexpectedEOF without knowing why.
	if _, err := fmt.Sscanf(comm, "(%s)", &pname); err != nil && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("could not scan '%s': %w", comm, err)
	}

	return &procStat{
		Pname: strings.TrimRight(pname, ")"),
		Ppid:  ppid,
		Pgrp:  pgrp,
	}, nil
}

func parseSocketInode(lnk string) (uint32, error) {
	const pattern = "socket:["
	ind := strings.Index(lnk, pattern)
	if ind == -1 {
		return 0, nil
	}
	var ino uint32
	n, err := fmt.Sscanf(lnk, "socket:[%d]", &ino)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, fmt.Errorf("'%s' should be pattern '[socket:\\%d]'", lnk, n)
	}
	return ino, nil
}
