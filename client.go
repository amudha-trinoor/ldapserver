package ldapserver

import (
	"bufio"
	"net"
	"sync"
	"time"

	ldap "github.com/lor00x/goldap/message"
)

type client struct {
	Numero      int
	srv         *Server
	rwc         net.Conn
	br          *bufio.Reader
	bw          *bufio.Writer
	chanOut     chan *ldap.LDAPMessage
	wg          sync.WaitGroup
	closing     chan bool
	requestList map[int]*Message
	mutex       sync.Mutex
	writeDone   chan bool
	rawData     []byte
}

func (c *client) GetConn() net.Conn {
	if c == nil {
		return nil
	}
	return c.rwc
}

func (c *client) GetRaw() []byte {
	if c == nil {
		return nil
	}
	return c.rawData
}

func (c *client) SetConn(conn net.Conn) {
	if c == nil {
		return
	}
	c.rwc = conn
	if c.rwc != nil {
		c.br = bufio.NewReader(c.rwc)
		c.bw = bufio.NewWriter(c.rwc)
	}
}

func (c *client) GetMessageByID(messageID int) (*Message, bool) {
	if c == nil || c.requestList == nil {
		return nil, false
	}
	if requestToAbandon, ok := c.requestList[messageID]; ok {
		return requestToAbandon, true
	}
	return nil, false
}

func (c *client) Addr() net.Addr {
	if c == nil || c.rwc == nil {
		return nil
	}
	return c.rwc.RemoteAddr()
}

func (c *client) ReadPacket() (*messagePacket, error) {
	if c == nil || c.br == nil {
		return nil, nil
	}
	mP, err := readMessagePacket(c.br)
	if err != nil {
		return nil, err
	}
	if mP != nil {
		c.rawData = make([]byte, len(mP.bytes))
		copy(c.rawData, mP.bytes)
	}
	return mP, nil
}

func (c *client) serve() {
	if c == nil {
		return
	}
	defer c.close()

	c.closing = make(chan bool)
	if c.srv != nil && c.srv.OnNewConnection != nil {
		if err := c.srv.OnNewConnection(c.rwc); err != nil {
			Logger.Printf("Erreur OnNewConnection: %s", err)
			return
		}
	}

	c.chanOut = make(chan *ldap.LDAPMessage)
	c.writeDone = make(chan bool)

	go func() {
		for msg := range c.chanOut {
			if msg != nil {
				c.writeMessage(msg)
			}
		}
		if c.writeDone != nil {
			close(c.writeDone)
		}
	}()

	go func() {
		for {
			select {
			case <-c.srv.chDone:
				if c.srv != nil {
					c.wg.Add(1)
					r := NewExtendedResponse(LDAPResultUnwillingToPerform)
					r.SetDiagnosticMessage("server is about to stop")
					r.SetResponseName(NoticeOfDisconnection)

					m := ldap.NewLDAPMessageWithProtocolOp(r)

					c.chanOut <- m
					c.wg.Done()
					if c.rwc != nil {
						c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
					}
				}
				return
			case <-c.closing:
				return
			}
		}
	}()

	c.requestList = make(map[int]*Message)

	for {
		if c.srv != nil {
			if c.srv.ReadTimeout != 0 && c.rwc != nil {
				c.rwc.SetReadDeadline(time.Now().Add(c.srv.ReadTimeout))
			}
			if c.srv.WriteTimeout != 0 && c.rwc != nil {
				c.rwc.SetWriteDeadline(time.Now().Add(c.srv.WriteTimeout))
			}
		}

		messagePacket, err := c.ReadPacket()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				Logger.Printf("Sorry client %d, i can not wait anymore (reading timeout) ! %s", c.Numero, err)
			} else {
				Logger.Printf("Error readMessagePacket: %s", err)
			}
			return
		}

		if messagePacket == nil {
			continue
		}

		message, err := messagePacket.readMessage()
		if err != nil {
			Logger.Printf("Error reading Message : %s\n\t%x", err.Error(), messagePacket.bytes)
			continue
		}
		Logger.Printf("<<< %d - %s - hex=%x", c.Numero, message.ProtocolOpName(), messagePacket)

		if _, ok := message.ProtocolOp().(ldap.UnbindRequest); ok {
			return
		}

		if req, ok := message.ProtocolOp().(ldap.ExtendedRequest); ok {
			if req.RequestName() == NoticeOfStartTLS {
				c.wg.Add(1)
				c.ProcessRequestMessage(&message)
				continue
			}
		}

		c.wg.Add(1)
		go c.ProcessRequestMessage(&message)
	}
}

func (c *client) close() {
	if c == nil {
		return
	}
	Logger.Printf("client %d close()", c.Numero)
	if c.closing != nil {
		close(c.closing)
	}

	if c.rwc != nil {
		c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
		Logger.Printf("client %d close() - stop reading from client", c.Numero)
	}

	c.mutex.Lock()
	if c.requestList != nil {
		for messageID, request := range c.requestList {
			Logger.Printf("Client %d close() - sent abandon signal to request[messageID = %d]", c.Numero, messageID)
			if request != nil {
				go request.Abandon()
			}
		}
	}
	c.mutex.Unlock()
	Logger.Printf("client %d close() - Abandon signal sent to processors", c.Numero)

	c.wg.Wait()
	if c.chanOut != nil {
		close(c.chanOut)
	}
	Logger.Printf("client [%d] request processors ended", c.Numero)

	if c.writeDone != nil {
		<-c.writeDone
	}
	if c.rwc != nil {
		c.rwc.Close()
		Logger.Printf("client [%d] connection closed", c.Numero)
	}
	if c.srv != nil {
		c.srv.wg.Done()
	}
}

func (c *client) writeMessage(m *ldap.LDAPMessage) {
	if c == nil || c.bw == nil || m == nil {
		return
	}
	data, _ := m.Write()
	Logger.Printf(">>> %d - %s - hex=%x", c.Numero, m.ProtocolOpName(), data.Bytes())
	c.bw.Write(data.Bytes())
	c.bw.Flush()
}

// ResponseWriter interface is used by an LDAP handler to
// construct an LDAP response.
type ResponseWriter interface {
	// Write writes the LDAPResponse to the connection as part of an LDAP reply.
	Write(po ldap.ProtocolOp)
}

type responseWriterImpl struct {
	chanOut   chan *ldap.LDAPMessage
	messageID int
}

func (w responseWriterImpl) Write(po ldap.ProtocolOp) {
	m := ldap.NewLDAPMessageWithProtocolOp(po)
	m.SetMessageID(w.messageID)
	w.chanOut <- m
}

func (c *client) ProcessRequestMessage(message *ldap.LDAPMessage) {
	if c == nil || message == nil {
		return
	}
	defer c.wg.Done()

	m := Message{
		LDAPMessage: message,
		Done:        make(chan bool, 2),
		Client:      c,
	}

	c.registerRequest(&m)
	defer c.unregisterRequest(&m)

	var w responseWriterImpl
	if c.chanOut != nil {
		w.chanOut = c.chanOut
	}
	w.messageID = m.MessageID().Int()

	if c.srv != nil && c.srv.Handler != nil {
		c.srv.Handler.ServeLDAP(w, &m)
	}
}

func (c *client) registerRequest(m *Message) {
	if c == nil || m == nil {
		return
	}
	c.mutex.Lock()
	if c.requestList != nil {
		c.requestList[m.MessageID().Int()] = m
	}
	c.mutex.Unlock()
}

func (c *client) unregisterRequest(m *Message) {
	if c == nil || m == nil {
		return
	}
	c.mutex.Lock()
	if c.requestList != nil {
		delete(c.requestList, m.MessageID().Int())
	}
	c.mutex.Unlock()
}
