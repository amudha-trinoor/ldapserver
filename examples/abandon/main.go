package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	ldap "github.com/amudha-trinoor/ldapserver"
)

func main() {
	//Create a new LDAP Server
	server := ldap.NewServer()
	// server.ReadTimeout = time.Millisecond * 100
	// server.WriteTimeout = time.Millisecond * 100
	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearch)
	server.Handle(routes)

	// listen on 10389
	go server.ListenAndServe("127.0.0.1:10389")

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	for {
		select {
		case <-m.Done:
			log.Printf("Leaving handleSearch... for msgid=%d", m.MessageID)
			return
		default:
		}

		e := ldap.NewSearchResultEntry("cn=Valere JEANTET, " + string(r.BaseObject()))
		e.AddAttribute("company", "CO")
		e.AddAttribute("department", "DEP")
		e.AddAttribute("l", "en")
		e.AddAttribute("mobile", "0612324567")
		e.AddAttribute("telephoneNumber", "0612324567")
		e.AddAttribute("cn", "Ecample User")
		w.Write(e)
		time.Sleep(time.Millisecond * 800)
	}

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)

}

// handleBind return Success for any login/pass
func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
	return
}
