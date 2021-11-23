package module

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type address struct {
	ip   string
	port uint16
}

func (a address) text() string {
	return fmt.Sprintf("%s:%d", a.ip, a.port)
}

type state uint8

const (
	sEstablished = iota + 1
	sSynSent
	sSynRecv
	sFinWait1
	sFinWait2
	sTimeWait
	sClose
	sCloseWait
	sLastAcl
	sListen
	sClosing
)

func (s state) text() string {
	switch s {
	case sEstablished:
		return "ESTABLISHED"
	case sSynSent:
		return "SYN_SENT"
	case sSynRecv:
		return "SYN_RECV"
	case sFinWait1:
		return "FIN_WAIT1"
	case sFinWait2:
		return "FIN_WAIT2"
	case sTimeWait:
		return "TIME_WAIT"
	case sClose:
		return "CLOSE"
	case sCloseWait:
		return "CLOSE_WAIT"
	case sLastAcl:
		return "LAST_ACL"
	case sListen:
		return "LISTEN"
	case sClosing:
		return "CLOSING"
	}
	return ""
}

type record struct {
	localAddress  address
	remoteAddress address
	state         state
	uid           uint32
	inode         uint32
}

type cmdline struct {
	pid  uint32
	text string
}

var ppidRegex = regexp.MustCompile(`PPid:\s*(\d+)`)

type records []record

func (r records) Len() int {
	return len(r)
}

func (r records) Less(i, j int) bool {
	return r[i].localAddress.port < r[j].localAddress.port
}

func (r records) Swap(i, j int) {
	tmp := r[i]
	r[i] = r[j]
	r[j] = tmp
}

type uint32s []uint32

func (u uint32s) Len() int {
	return len(u)
}

func (u uint32s) Less(i, j int) bool {
	return u[i] < u[j]
}

func (u uint32s) Swap(i, j int) {
	tmp := u[i]
	u[i] = u[j]
	u[j] = tmp
}

func (r record) text() string {
	return fmt.Sprintf("%s %s %s %5d %5d", r.localAddress.text(), r.remoteAddress.text(), r.state.text(), r.uid, r.inode)
}

func PrintPortListen() {
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		exit(err)
	}
	defer file.Close()

	pidMapping := getPidMapping()
	portsMap := make(map[uint32]records)
	scanner := bufio.NewScanner(file)
	scanner.Scan()

	for scanner.Scan() {
		r := parseRecord(scanner.Text())
		if r.state != sListen {
			continue
		}
		pid := pidMapping[r.inode]
		ports, ok := portsMap[pid]
		if !ok {
			ports = make([]record, 0)
		}
		portsMap[pid] = append(ports, r)
	}
	pids := make(uint32s, len(portsMap))
	i := 0
	for k := range portsMap {
		pids[i] = k
		i++
	}
	sort.Sort(pids)
	for _, k := range pids {
		ports := portsMap[k]
		cmd := getCmdline(k)
		sort.Sort(&ports)
		println(cmd)
		for _, port := range ports {
			println(fmt.Sprintf("%s ─ %s%s", colorRed, port.localAddress.text(), colorReset))
		}
	}
}

func getPidMapping() (mapping map[uint32]uint32) {
	dirs, err := ioutil.ReadDir("/proc")
	if err != nil {
		exit(err)
	}
	mapping = make(map[uint32]uint32)
	for _, dir := range dirs {
		if !dir.IsDir() || !isDigest(dir.Name()) {
			continue
		}
		pid, _ := strconv.ParseUint(dir.Name(), 10, 32)
		path := "/proc/" + dir.Name() + "/fd"
		fds, _ := ioutil.ReadDir(path)
		for _, fd := range fds {
			link, _ := os.Readlink(path + "/" + fd.Name())
			has := strings.HasPrefix(link, "socket:")
			if !has {
				continue
			}
			inode, _ := strconv.ParseUint(link[8:len(link)-1], 10, 32)
			mapping[uint32(inode)] = uint32(pid)
		}
	}
	return
}

func getCmdline(pid uint32) string {
	cmdlines := []cmdline{getCmdline0(pid)}
	i := 0
	for {
		ppid := getPpid(pid)
		if ppid <= 1 {
			break
		}
		pcmdline := getCmdline0(ppid)
		if pcmdline.text == "" {
			break
		}
		cmdlines = append(cmdlines, pcmdline)
		pid = ppid
		i++
	}
	for i, j := 0, len(cmdlines)-1; i < j; i, j = i+1, j-1 {
		cmdlines[i], cmdlines[j] = cmdlines[j], cmdlines[i]
	}
	cmdlineTexts := make([]string, len(cmdlines))
	for i, cmdline := range cmdlines {
		c := ""
		if i > 0 {
			c = "└─ "
		}
		cmdlineTexts[i] = fmt.Sprintf("%s%s%s%s%s%s#%d%s",
			strings.Repeat("  ", i),
			colorGreen, c, cmdline.text, colorReset,
			colorYellow, cmdline.pid, colorReset)
	}

	return strings.Join(cmdlineTexts, "\n")
}

func getCmdline0(pid uint32) cmdline {
	bytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	var cmd string
	if err == nil {
		cmd = parseCmdlineString(bytes)
	}
	return cmdline{
		pid:  pid,
		text: cmd,
	}
}

func getPpid(pid uint32) uint32 {
	bytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	find := ppidRegex.FindStringSubmatch(string(bytes))
	if len(find) > 1 {
		ppid, _ := strconv.ParseUint(find[1], 10, 32)
		return uint32(ppid)
	}
	return 0
}

func parseCmdlineString(bytes []byte) string {
	for i, b := range bytes {
		if b == 0 {
			bytes[i] = ' '
		}
	}
	return string(bytes)
}

func isDigest(str string) bool {
	for _, c := range str {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func parseRecord(text string) record {
	fields := strings.Fields(text)
	s, _ := strconv.ParseUint(fields[3], 16, 16)
	uid, _ := strconv.ParseUint(fields[7], 10, 32)
	inode, _ := strconv.ParseUint(fields[9], 10, 32)
	return record{
		localAddress:  parseAddress(fields[1]),
		remoteAddress: parseAddress(fields[2]),
		state:         state(s),
		uid:           uint32(uid),
		inode:         uint32(inode),
	}
}

func parseAddress(str string) address {
	idx := strings.Index(str, ":")
	return address{
		ip:   parseIPv4(str[:idx]),
		port: parsePort(str[idx+1:]),
	}
}

func parseIPv4(str string) string {
	bytes := make([]byte, 4)
	_, _ = hex.Decode(bytes, []byte(str))
	return fmt.Sprintf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0])
}

func parsePort(str string) uint16 {
	bytes := make([]byte, 2)
	_, _ = hex.Decode(bytes, []byte(str))
	return (uint16(bytes[0]) << 8) | uint16(bytes[1])
}

func exit(err error) {
	println("ERROR: " + err.Error())
	os.Exit(-1)
}
