// Copyright 2020 Dean.
// Authors: Dean <dean@csoio.com>
// Date: 2020/9/25 10:25 上午

//go:build !linux

package goss

import "errors"

func Connections(family AddressFamily, kind string) ([]*Stat, error) {
	return nil, errors.New("not implemented")
}
