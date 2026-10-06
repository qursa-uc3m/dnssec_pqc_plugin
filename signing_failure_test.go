package dnssec_pqc

import (
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestSigningFailureReturnsSERVFAIL(t *testing.T) {
	d, rm1, rm2 := newDnssec(t, []string{"miek.nl."})
	defer rm1()
	defer rm2()
	d.keys = nil
	m := testMsg()
	state := request.Request{Req: m, Zone: "miek.nl."}
	got := d.Sign(state, time.Now().UTC(), server)
	if got.Rcode != dns.RcodeServerFailure || len(got.Answer) != 0 || len(got.Ns) != 0 {
		t.Fatalf("signing failure produced non-SERVFAIL or partial answer: %+v", got)
	}
}
