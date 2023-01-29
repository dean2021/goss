// Copyright 2020 Dean.
// Authors: Dean <dean@csoio.com>
// Date: 2020/9/25 10:25 上午

//go:build !linux

package goss

import "errors"

type AddressFamily uint8

// https://github.com/torvalds/linux/blob/5924bbecd0267d87c24110cbe2041b5075173a25/include/linux/socket.h#L159
const (
	AF_INET  AddressFamily = 2
	AF_INET6 AddressFamily = 10
)

func Connections(family AddressFamily, kind string) ([]*Stat, error) {
	return nil, errors.New("not implemented")
}

type InetDiagMsg uint8

func ConnectionsWithProtocol(family AddressFamily, protocol uint8) ([]*InetDiagMsg, error) {
	return nil, errors.New("not implemented")
}
