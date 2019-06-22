// Golang SSH daemon
// Based off: https://gist.github.com/jpillora/b480fde82bff51a06238
//
// Server:
// cd my/new/dir/
// #generate server keypair
// ssh-keygen -t rsa
// go get -v .
// go run sshd.go
//
// Client:
// ssh foo@localhost -p 2200

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
	"bytes"
	"github.com/BurntSushi/toml"
	"github.com/coreos/go-systemd/daemon"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
	"crypto/subtle"
	//"golang.org/x/crypto/ssh/terminal"
)

type Conf struct {
	Whitelist []string
	WhitelistCIDR []*net.IPNet
}

var (
	C        *Conf
	Verbose  bool
)

func Init(path string) error {
	r, e := os.Open(path)
	if e != nil {
		return e
	}
	defer r.Close()

	C = new(Conf)
	if _, e := toml.DecodeReader(r, &C); e != nil {
		return fmt.Errorf("TOML: %s", e)
	}
	for _, ip := range C.Whitelist {
		_, cidr, e := net.ParseCIDR(ip)
		if e != nil {
			return e
		}
		C.WhitelistCIDR = append(C.WhitelistCIDR, cidr)
	}
	return nil
}


func main() {
	flag.BoolVar(&Verbose, "v", false, "Verbose-mode (log more)")
	flag.Parse()

	if e := Init("./config.toml"); e != nil {
		panic(e)
	}

	/*listeners, e := activation.Listeners()
	if e != nil {
		panic(e)
	}
	if len(listeners) != 2 {
		panic(fmt.Errorf("fd.socket activation (%d != 2)\n", len(listeners)))
	}*/

	var userkey []byte
	{
		userbytes, e := ioutil.ReadFile("authorized_keys")
		if e != nil {
			panic(e)
		}
		userlines := bytes.SplitN(userbytes, []byte("\n"), 2)
		if len(userlines) != 1 && len(userlines[1]) > 2 {
			fmt.Printf("%s\n", userlines)
			panic("authorized_keys exceeds limit of 1-key?")
		}
		userkey = bytes.TrimSpace(userlines[0])

		toks := bytes.SplitN(userkey, []byte(" "), 3)
		if len(toks) == 3 {
			// Strip out comment
			userkey = bytes.Join(toks[:2], []byte(" "))
		}
	}

	// In the latest version of crypto/ssh (after Go 1.3), the SSH server type has been removed
	// in favour of an SSH connection type. A ssh.ServerConn is created by passing an existing
	// net.Conn and a ssh.ServerConfig to ssh.NewServerConn, in effect, upgrading the net.Conn
	// into an ssh.ServerConn

	config := &ssh.ServerConfig{
		Config: ssh.Config{
			//Ciphers: "aes128-ctr, aes192-ctr, aes256-ctr, aes128-gcm@openssh.com",
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			clientKey := bytes.TrimSpace(ssh.MarshalAuthorizedKey(key))
			if subtle.ConstantTimeCompare(clientKey, userkey) == 1 {
				return &ssh.Permissions{Extensions: map[string]string{"key-id": "1"}}, nil
			}
			//fmt.Printf("Mismatch pubkeys.\nFound=%s\nWant=%s\n", clientKey, userkey)
			return nil, fmt.Errorf("pubkey reject for %q", c.User())
		},
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return "ALERT! All connections are monitored and recorded.\nDisconnect IMMEDIATELY if you are not an authorized user!\n"
		},

		PasswordCallback: nil, // don't allow pass
		MaxAuthTries: 1,
		NoClientAuth: false,
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", ":2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	// Accept all connections
	if Verbose {
		log.Print("Listening on 2200...")
	}

	sent, e := daemon.SdNotify(false, "READY=1")
	if e != nil {
		log.Fatal(e)
	}
	if !sent {
		log.Printf("SystemD notify NOT sent\n")
	}

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		addr, ok := tcpConn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			log.Printf("Failed convert conn to TCPAddr (%s)", addr)
			continue
		}

		ok = false
		for _, cidr := range C.WhitelistCIDR {
			if Verbose {
				log.Printf("IP.check(%s, %s) ", cidr, addr.IP)
			}
			if cidr.Contains(addr.IP) {
				if Verbose {
					log.Printf("match!\n")
				}
				ok = true
				break
			}

			if Verbose {
				log.Printf("no!\n")
			}
		}
		if !ok {
			tcpConn.Write([]byte("IP not allowed.\n"))
			tcpConn.Close()
			continue
		}

		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("ssh.begin(%s) user=%s version=%s", sshConn.RemoteAddr(), sshConn.User(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(sshConn, chans)
	}
}

func handleChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(sshConn, newChannel)
	}
}

func handleChannel(sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Fire up bash for this session
	bash := exec.Command("bash")
	bash.Env = []string{"TERM=vt100"}

	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		}
		log.Printf("ssh.close(%s) user=%s", sshConn.RemoteAddr(), sshConn.User())
	}

	// Allocate a terminal for this channel
	bashf, err := pty.Start(bash)
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		close()
		return
	}
	// TODO defer bashf.Close()

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

// Borrowed from https://github.com/creack/termios/blob/master/win/win.go
