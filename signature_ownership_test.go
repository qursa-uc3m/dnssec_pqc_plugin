package dnssec_pqc

import (
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestSignatureResponseOwnership(t *testing.T) {
	d, rm1, rm2 := newDnssec(t, []string{"miek.nl."})
	defer rm1()
	defer rm2()
	rr, err := dns.NewRR("test.miek.nl. 5 IN A 10.250.0.1")
	if err != nil {
		t.Fatal(err)
	}
	rrset := []dns.RR{rr}
	inception, expiration := incepExpir(time.Now())
	first, err := d.sign(rrset, "miek.nl.", 5, inception, expiration, "ownership")
	if err != nil || len(first) != 1 {
		t.Fatalf("signing: %v %v", first, err)
	}
	// The downstream response cache ages TTLs. It must not alter a stored signature.
	if first[0].(*dns.RRSIG).OrigTtl != 5 {
		t.Fatal("Original TTL differs from the signed RRset")
	}
	if err := first[0].(*dns.RRSIG).Verify(d.keys[0].K, rrset); err != nil {
		t.Fatal(err)
	}
	first[0].Header().Ttl = 1
	second, err := d.sign(rrset, "miek.nl.", 5, inception, expiration, "ownership")
	if err != nil {
		t.Fatal(err)
	}
	if second[0].Header().Ttl != 5 {
		t.Fatalf("response cache changed signature cache TTL to %d", second[0].Header().Ttl)
	}
	second[0].Header().Ttl = 2
	third, err := d.sign(rrset, "miek.nl.", 5, inception, expiration, "ownership")
	if err != nil {
		t.Fatal(err)
	}
	if third[0].Header().Ttl != 5 {
		t.Fatal("cache hits share mutable signature records")
	}
}
