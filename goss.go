// Copyright 2020 Dean.
// Authors: Dean <dean@csoio.com>
// Date: 2020/9/25 10:25 上午

package goss

import (
	"syscall"
)

var netConnectionKindMap = map[string][]uint8{
	"all": {syscall.IPPROTO_TCP, syscall.IPPROTO_UDP},
	"tcp": {syscall.IPPROTO_TCP},
	"udp": {syscall.IPPROTO_UDP},
}

var netProtocolKindMap = map[uint8]string{
	syscall.IPPROTO_TCP: "tcp",
	syscall.IPPROTO_UDP: "udp",
}

// AddrPort are <addr>:<port>
type AddrPort struct {
	Addr string `json:"addr"`
	Port string `json:"port"`
}

// Stat represents a socket statistics.
type Stat struct {
	Proto   string    `json:"proto"`
	RecvQ   uint32    `json:"recvq"`
	SendQ   uint32    `json:"sendq"`
	Local   *AddrPort `json:"local"`
	Foreign *AddrPort `json:"foreign"`
	State   string    `json:"state"`
	Inode   uint32    `json:"inode"`
	Process *UserEnt  `json:"process"`
}

// UserEnt represents a detail of network socket.
// see https://github.com/shemminger/iproute2/blob/afa588490b7e87c5adfb05d5163074e20b6ff14a/misc/ss.c#L509.
type UserEnt struct {
	Inode uint32 `json:"inode"`  // inode number
	FD    int    `json:"fd"`     // file discryptor
	Pid   int    `json:"pid"`    // process id
	PName string `json:"p_name"` // process name
	PPid  int    `json:"p_pid"`  // parent process id
	PGid  int    `json:"p_gid"`  // process group id
}
