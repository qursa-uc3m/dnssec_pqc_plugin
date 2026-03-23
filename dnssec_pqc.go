// Package dnssec implements a plugin that signs responses on-the-fly using
// NSEC black lies.
package dnssec_pqc

import (
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/coredns/coredns/plugin/pkg/singleflight"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// Dnssec signs the reply on-the-fly.
type Dnssec struct {
	Next plugin.Handler

	zones     []string
	keys      []*DNSKEY
	splitkeys bool
	inflight  *singleflight.Group
	cache     *cache.Cache
	noCache   bool // when true, skip signature cache (cache_capacity 0)

	// Simulated signing delay for controlled-cost experiments.
	// The delay is injected inside singleflight.Do, after the real
	// cryptographic operation, so it behaves like a slower algorithm.
	simulatedDelay  time.Duration
	simulatedStddev time.Duration
}

// New returns a new Dnssec.
func New(zones []string, keys []*DNSKEY, splitkeys bool, next plugin.Handler, c *cache.Cache, capacity int, simDelay, simStddev time.Duration) Dnssec {
	return Dnssec{Next: next,
		zones:           zones,
		keys:            keys,
		splitkeys:       splitkeys,
		cache:           c,
		noCache:         capacity <= 0,
		inflight:        new(singleflight.Group),
		simulatedDelay:  simDelay,
		simulatedStddev: simStddev,
	}
}

// Sign signs the message in state. it takes care of negative or nodata responses. It
// uses NSEC black lies for authenticated denial of existence. For delegations it
// will insert DS records and sign those.
// Signatures will be cached for a short while. By default we sign for 8 days,
// starting 3 hours ago.
func (d Dnssec) Sign(state request.Request, now time.Time, server string) *dns.Msg {
	req := state.Req

	incep, expir := incepExpir(now)

	mt, _ := response.Typify(req, time.Now().UTC()) // TODO(miek): need opt record here?
	if mt == response.Delegation {
		// We either sign DS or NSEC of DS.
		ttl := req.Ns[0].Header().Ttl

		ds := []dns.RR{}
		for i := range req.Ns {
			if req.Ns[i].Header().Rrtype == dns.TypeDS {
				ds = append(ds, req.Ns[i])
			}
		}
		if len(ds) == 0 {
			if sigs, err := d.nsec(state, mt, ttl, incep, expir, server); err == nil {
				req.Ns = append(req.Ns, sigs...)
			} else {
				log.Warningf("Unsigned NSEC for delegation: zone=%s err=%v", state.Zone, err)
			}
		} else if sigs, err := d.sign(ds, state.Zone, ttl, incep, expir, server); err == nil {
			req.Ns = append(req.Ns, sigs...)
		} else {
			log.Warningf("Unsigned DS: zone=%s err=%v", state.Zone, err)
		}
		return req
	}

	if mt == response.NameError || mt == response.NoData {
		if req.Ns[0].Header().Rrtype != dns.TypeSOA || len(req.Ns) > 1 {
			return req
		}

		ttl := req.Ns[0].Header().Ttl

		if sigs, err := d.sign(req.Ns, state.Zone, ttl, incep, expir, server); err == nil {
			req.Ns = append(req.Ns, sigs...)
		} else {
			log.Warningf("Unsigned SOA: zone=%s err=%v", state.Zone, err)
		}
		if sigs, err := d.nsec(state, mt, ttl, incep, expir, server); err == nil {
			req.Ns = append(req.Ns, sigs...)
		}
		if len(req.Ns) > 1 { // actually added nsec and sigs, reset the rcode
			req.Rcode = dns.RcodeSuccess
			if state.QType() == dns.TypeNSEC { // If original query was NSEC move Ns to Answer without SOA
				req.Answer = req.Ns[len(req.Ns)-2 : len(req.Ns)]
				req.Ns = nil
			}
		}
		return req
	}

	for _, r := range rrSets(req.Answer) {
		ttl := r[0].Header().Ttl
		if sigs, err := d.sign(r, state.Zone, ttl, incep, expir, server); err == nil {
			req.Answer = append(req.Answer, sigs...)
		} else {
			log.Warningf("Unsigned Answer RRset: name=%s type=%d err=%v", r[0].Header().Name, r[0].Header().Rrtype, err)
		}
	}
	for _, r := range rrSets(req.Ns) {
		ttl := r[0].Header().Ttl
		if sigs, err := d.sign(r, state.Zone, ttl, incep, expir, server); err == nil {
			req.Ns = append(req.Ns, sigs...)
		} else {
			log.Warningf("Unsigned Ns RRset: name=%s type=%d err=%v", r[0].Header().Name, r[0].Header().Rrtype, err)
		}
	}
	for _, r := range rrSets(req.Extra) {
		ttl := r[0].Header().Ttl
		if sigs, err := d.sign(r, state.Zone, ttl, incep, expir, server); err == nil {
			req.Extra = append(req.Extra, sigs...)
		} else {
			log.Warningf("Unsigned Extra RRset: name=%s type=%d err=%v", r[0].Header().Name, r[0].Header().Rrtype, err)
		}
	}
	return req
}

func (d Dnssec) sign(rrs []dns.RR, signerName string, ttl, incep, expir uint32, server string) ([]dns.RR, error) {
	k := hash(rrs)
	sgs, ok := d.get(k, server)
	if ok {
		return sgs, nil
	}
	// Track whether this goroutine was the singleflight leader (executed fn)
	// or a coalesced waiter (shared the result).
	var executed int32
	sigs, err := d.inflight.Do(k, func() (interface{}, error) {
		atomic.StoreInt32(&executed, 1)
		start := time.Now()

		var sigs []dns.RR
		for _, k := range d.keys {
			if d.splitkeys {
				if len(rrs) > 0 && rrs[0].Header().Rrtype == dns.TypeDNSKEY {
					// We are signing a DNSKEY RRSet. With split keys, we need to use a KSK here.
					if !k.isKSK() {
						continue
					}
				} else {
					// For non-DNSKEY RRSets, we want to use a ZSK.
					if !k.isZSK() {
						continue
					}
				}
			}
			sig := k.newRRSIG(signerName, ttl, incep, expir)
			if e := sig.SignWithPQC(k.s, rrs, k.privRaw); e != nil {
				log.Errorf("SignWithPQC failed: alg=%d tag=%d name=%s rrtype=%d err=%v",
					k.K.Algorithm, k.tag, rrs[0].Header().Name, rrs[0].Header().Rrtype, e)
				signErrors.WithLabelValues(server).Inc()
				return sigs, e
			}
			sigs = append(sigs, sig)
		}
		// Simulated signing delay: injected inside singleflight.Do so
		// concurrent waiters experience the same queueing as a real
		// slow algorithm would produce.
		if d.simulatedDelay > 0 {
			delay := d.simulatedDelay
			if d.simulatedStddev > 0 {
				jitter := time.Duration(rand.NormFloat64() * float64(d.simulatedStddev))
				delay += jitter
			}
			if delay > 0 {
				time.Sleep(delay)
			}
		}

		signDuration.WithLabelValues(server).Observe(time.Since(start).Seconds())
		singleflightExecs.WithLabelValues(server).Inc()

		d.set(k, sigs)
		return sigs, nil
	})
	if atomic.LoadInt32(&executed) == 0 {
		singleflightCoalesced.WithLabelValues(server).Inc()
	}
	return sigs.([]dns.RR), err
}

func (d Dnssec) set(key uint64, sigs []dns.RR) {
	if d.noCache {
		return
	}
	d.cache.Add(key, sigs)
}

func (d Dnssec) get(key uint64, server string) ([]dns.RR, bool) {
	if d.noCache {
		cacheMisses.WithLabelValues(server).Inc()
		return nil, false
	}
	if s, ok := d.cache.Get(key); ok {
		// we sign for 8 days, check if a signature in the cache reached 3/4 of that
		is75 := time.Now().UTC().Add(twoDays)
		for _, rr := range s.([]dns.RR) {
			if !rr.(*dns.RRSIG).ValidityPeriod(is75) {
				cacheMisses.WithLabelValues(server).Inc()
				return nil, false
			}
		}

		cacheHits.WithLabelValues(server).Inc()
		return s.([]dns.RR), true
	}
	cacheMisses.WithLabelValues(server).Inc()
	return nil, false
}

func incepExpir(now time.Time) (uint32, uint32) {
	incep := uint32(now.Add(-3 * time.Hour).Unix()) // -(2+1) hours, be sure to catch daylight saving time and such
	expir := uint32(now.Add(eightDays).Unix())      // sign for 8 days
	return incep, expir
}

const (
	eightDays  = 8 * 24 * time.Hour
	twoDays    = 2 * 24 * time.Hour
	defaultCap = 10000 // default capacity of the cache.
)
