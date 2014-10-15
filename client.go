package ldapserver

import (
	"bufio"
	"log"
	"net"
	"reflect"
	"time"
)

type client struct {
	Numero    int
	srv       *Server
	rwc       net.Conn
	br        *bufio.Reader
	bw        *bufio.Writer
	chan_out  chan LDAPResponse
	helloType string
	helloHost string
}

func (s *client) errorf(format string, args ...interface{}) {
	log.Printf("Client error: "+format, args...)
}

func (s *client) Addr() net.Addr {
	return s.rwc.RemoteAddr()
}

func (c *client) serve() {
	defer c.rwc.Close()
	if onc := c.srv.OnNewConnection; onc != nil {
		if err := onc(c.rwc); err != nil {
			log.Printf("Erreur OnNewConnection: %s", err)
			return
		}
	}

	c.chan_out = make(chan LDAPResponse, 20)

	done := make(chan bool)

	go func() {
		for {
			select {
			case <-done:
				c.close()
				log.Print("-------------- Leaving because of channel")
				break
			case msg := <-c.chan_out:
				log.Printf("------------- channel msg=%T", msg)
				c.writeLdapResult(msg)
			}
		}
	}()

	for {

		if c.srv.ReadTimeout != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(c.srv.ReadTimeout))
		}

		//Read the ASN1/BER binary message
		message_packet, err := readMessagePacket(c.br)
		if err != nil {
			log.Printf("Erreur readMessagePacket: %s", err)
			return
		}

		log.Printf("input hex=%x", message_packet.Packet.Bytes())

		//Convert binaryMessage to a ldap RequestMessage
		var ldap_request LDAPRequest
		ldap_request, err = message_packet.getRequestMessage()

		if err != nil {
			log.Printf("Error : %s", err.Error())
			break
		}

		//@Todo When the ldap_request can not be buffered, send a BusyLdapMessage
		log.Printf(">>>>>>>>>>>>>> [%d] %s", c.Numero, reflect.TypeOf(ldap_request).Name())

		if _, ok := ldap_request.(UnbindRequest); ok {
			done <- true
			break
		} else {
			go c.ProcessRequestMessage(ldap_request)
		}

	}
}

func (c *client) close() {
	c.rwc.Close()
	log.Printf("Connection client [%d] closed", c.Numero)
}

func (c *client) writeLdapResult(lr LDAPResponse) {
	data := lr.encodeToAsn1()
	log.Printf("write hex=%x", data)
	log.Printf("client=%v", c)
	c.bw.Write(data)
	c.bw.Flush()
}

func (c *client) ProcessRequestMessage(ldap_request LDAPRequest) {

	switch v := ldap_request.(type) {
	case BindRequest:
		var req = ldap_request.(BindRequest)
		req.SetClient(c)
		var res = BindResponse{Request: &req}
		c.srv.BindHandler(res, &req)

		if req.wroteMessage == 0 {
			res.ResultCode = LDAPResultSuccess
			c.chan_out <- res
			req.wroteMessage += 1
		}

	case SearchRequest:
		var req SearchRequest = ldap_request.(SearchRequest)

		req.SetClient(c)
		var r = SearchResponse{Request: &req}
		c.srv.SearchHandler(r, &req)

		if req.searchResultDoneSent == false {
			r.ResultCode = LDAPResultSuccess
			c.chan_out <- r
			req.wroteMessage += 1
		}

	case UnbindRequest:
		log.Fatal("Unbind Request sould not be handled here")

	default:
		log.Fatalf("unexpected type %T", v)
	}
}