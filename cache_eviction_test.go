package dnssec_pqc

import (
	"github.com/coredns/coredns/plugin/pkg/cache"
	dto "github.com/prometheus/client_model/go"
	"testing"
)

func TestSignatureCacheEvictionCounter(t *testing.T) {
	d := Dnssec{cache: cache.New(1024)}
	value := func() float64 {
		metric := new(dto.Metric)
		if err := cacheEvictions.Write(metric); err != nil {
			t.Fatal(err)
		}
		return metric.GetCounter().GetValue()
	}
	before := value()
	for i := uint64(0); i < 4; i++ {
		d.set(i*256, nil)
	}
	d.set(0, nil)
	if value() != before {
		t.Fatal("replacement counted as eviction")
	}
	d.set(4*256, nil)
	if value() != before+1 {
		t.Fatal("full shard eviction not counted")
	}
	if d.cache.Len() != 4 {
		t.Fatal("cache policy or capacity changed")
	}
}
