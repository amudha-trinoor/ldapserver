package ldapserver

import (
	"bufio"
	"net"
	"sync"
	"time"
)

// Server is an LDAP server.
type Server struct {
	Listener     net.Listener
	ReadTimeout  time.Duration  // optional read timeout
	WriteTimeout time.Duration  // optional write timeout
	wg           sync.WaitGroup // group of goroutines (1 by client)
	chDone       chan bool      // Channel Done, value => shutdown

	// OnNewConnection, if non-nil, is called on new connections.
	// If it returns non-nil, the connection is closed.
	OnNewConnection func(c net.Conn) error

	// Handler handles ldap message received from client
	// it SHOULD "implement" RequestHandler interface
	Handler Handler
}

// NewServer return a LDAP Server
func NewServer() *Server {
	return &Server{
		chDone: make(chan bool),
	}
}

// Handle registers the handler for the server.
// If a handler already exists for pattern, Handle panics
func (s *Server) Handle(h Handler) {
	if s == nil {
		return
	}
	if s.Handler != nil {
		panic("PANIC: LDAP: multiple Handler registrations")
	}
	s.Handler = h
}

// ListenAndServe listens on the TCP network address s.Addr and then
// calls Serve to handle requests on incoming connections.  If
// s.Addr is blank, ":389" is used.
func (s *Server) ListenAndServe(addr string, options ...func(*Server)) error {

	if addr == "" {
		addr = ":389"
	}

	var e error
	s.Listener, e = net.Listen("tcp", addr)
	if e != nil {
		return e
	}
	Logger.Printf("Listening on %s\n", addr)

	for _, option := range options {
		option(s)
	}

	return s.Serve()
}

// Handle requests messages on the ln listener
func (s *Server) Serve() error {
	if s == nil || s.Listener == nil {
		return nil
	}
	defer s.Listener.Close()

	if s.Handler == nil {
		Logger.Panicln("PANIC: No LDAP Request Handler defined")
	}

	i := 0

	for {
		select {
		case <-s.chDone:
			Logger.Print("Stopping server")
			if s.Listener != nil {
				s.Listener.Close()
			}
			return nil
		default:
		}

		rw, err := s.Listener.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			Logger.Println(err)
			continue
		}

		if s.ReadTimeout != 0 && rw != nil {
			rw.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}
		if s.WriteTimeout != 0 && rw != nil {
			rw.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}

		cli, err := s.newClient(rw)
		if err != nil {
			continue
		}

		i = i + 1
		if cli != nil {
			cli.Numero = i
			if cli.rwc != nil && cli.rwc.RemoteAddr() != nil {
				Logger.Printf("Connection client [%d] from %s accepted", cli.Numero, cli.rwc.RemoteAddr().String())
			}
			s.wg.Add(1)
			go cli.serve()
		}
	}

}

// Return a new session with the connection
// client has a writer and reader buffer
func (s *Server) newClient(rwc net.Conn) (c *client, err error) {
	if s == nil || rwc == nil {
		return nil, nil
	}
	c = &client{
		srv: s,
		rwc: rwc,
		br:  bufio.NewReader(rwc),
		bw:  bufio.NewWriter(rwc),
	}
	return c, nil
}

// Termination of the LDAP session is initiated by the server sending a
// Notice of Disconnection.  In this case, each
// protocol peer gracefully terminates the LDAP session by ceasing
// exchanges at the LDAP message layer, tearing down any SASL layer,
// tearing down any TLS layer, and closing the transport connection.
// A protocol peer may determine that the continuation of any
// communication would be pernicious, and in this case, it may abruptly
// terminate the session by ceasing communication and closing the
// transport connection.
// In either case, when the LDAP session is terminated.
func (s *Server) Stop() {
	if s == nil || s.chDone == nil {
		return
	}
	close(s.chDone)
	Logger.Print("gracefully closing client connections...")
	s.wg.Wait()
	Logger.Print("all clients connection closed")
}
