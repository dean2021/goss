## GoSS 

    goss是用于分析网络连接工具，基于golang开发, 可作为golang包引入使用，实现原理参考ss命令.
    他的最大特点是快, 当你的系统有上万个tcp链接要了解的时候的时候, netstat等常规工具变成废铁了, 这时候他的作用就非常明显了.
    
## 原理

    ss 快的秘诀在于，它利用到了 TCP 协议栈中 tcp_diag/udp_tcp_diag。tcp_diag/udp_tcp_diag 是一个用于分析统计的模块，
    可以获得 Linux 内核中第一手的信息，这就确保了获取网络连接的快捷高效.
    
### 注意
    目前仅支持linux环境运行
    
### TODO
- [ ] 支持windows
- [ ] 支持darwin

### 使用

main.go 
```go
package main

import (
	"encoding/json"
	"fmt"
	"github.com/dean2021/goss"
)

func main() {
	connections, err := goss.Connections("all")
	if err != nil{
		panic(err)
	}
	for _, conn := range connections {
		s, _ := json.Marshal(conn)
		fmt.Println(string(s))
	}
}
```
输出:
```json
{"proto":"tcp","recvq":0,"sendq":128,"local":{"addr":"0.0.0.0","port":"22"},"foreign":{"addr":"0.0.0.0","port":"0"},"state":"LISTEN","inode":17526,"process":null}
{"proto":"tcp","recvq":0,"sendq":0,"local":{"addr":"10.211.55.18","port":"22"},"foreign":{"addr":"10.211.55.2","port":"60443"},"state":"ESTAB","inode":94365,"process":null}
{"proto":"tcp","recvq":0,"sendq":0,"local":{"addr":"10.211.55.18","port":"22"},"foreign":{"addr":"10.211.55.2","port":"52681"},"state":"ESTAB","inode":40101,"process":null}
{"proto":"tcp","recvq":0,"sendq":0,"local":{"addr":"10.211.55.18","port":"22"},"foreign":{"addr":"10.211.55.2","port":"60305"},"state":"ESTAB","inode":94290,"process":null}
{"proto":"udp","recvq":0,"sendq":0,"local":{"addr":"127.0.0.1","port":"323"},"foreign":{"addr":"0.0.0.0","port":"0"},"state":"UNCONN","inode":14002,"process":null}
{"proto":"udp","recvq":0,"sendq":0,"local":{"addr":"0.0.0.0","port":"8888"},"foreign":{"addr":"0.0.0.0","port":"0"},"state":"UNCONN","inode":95273,"process":{"inode":95273,"fd":4,"pid":27246,"p_name":"nc","p_pid":27222,"p_gid":27246}}
{"proto":"udp","recvq":0,"sendq":0,"local":{"addr":"0.0.0.0","port":"68"},"foreign":{"addr":"0.0.0.0","port":"0"},"state":"UNCONN","inode":92582,"process":null}
```


## 参考/感谢

1. github.com/elastic/gosigar/sys/linux
2. https://github.com/yuuki/lstf
