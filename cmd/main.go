// Copyright 2020 Dean.
// Authors: Dean <dean@csoio.com>
// Date: 2020/9/25 10:25 上午

package main

import (
	"encoding/json"
	"fmt"

	"github.com/dean2021/goss"
)

func main() {
	connections, err := goss.Connections(goss.AF_INET, "all")
	if err != nil {
		panic(err)
	}
	for _, conn := range connections {
		s, _ := json.Marshal(conn)
		fmt.Println(string(s))
	}

	connectionsV6, err := goss.Connections(goss.AF_INET6, "all")
	if err != nil {
		panic(err)
	}
	for _, conn := range connectionsV6 {
		s, _ := json.Marshal(conn)
		fmt.Println(string(s))
	}
}
