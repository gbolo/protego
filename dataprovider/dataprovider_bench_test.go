package dataprovider

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// ---------- shared providers per implementation ----------

// providerCache stores a single Provider instance per implementation.
type providerCache struct {
	once sync.Once
	p    Provider
	err  error
}

// We support two implementations: "memory" and "bolt".
var benchProviderCache = map[string]*providerCache{
	"memory": {},
	"bolt":   {},
}

// getBenchmarkProvider returns a single Provider instance for the given impl.
// It lazily initializes the provider once using sync.Once.
//
// Assumes:
//   - NewMemoryProvider() (Provider, error) OR (*MemoryProvider, error)
//   - NewBoltProvider() (Provider, error) OR (*BoltProvider, error)
//
// In either case, the concrete type must satisfy the Provider interface.
func getBenchmarkProvider(b *testing.B, impl string) Provider {
	b.Helper()

	cache, ok := benchProviderCache[impl]
	if !ok {
		b.Fatalf("unknown provider implementation: %q", impl)
	}

	cache.once.Do(func() {
		var p Provider

		switch impl {
		case "memory":
			mp, err := NewMemoryProvider()
			if err != nil {
				cache.err = fmt.Errorf("NewMemoryProvider: %w", err)
				return
			}
			p = &mp

		case "bolt":
			// Create a temp file for bolt
			boltDbFile, errTempFile := os.CreateTemp("", "protego-bolt-*.db")
			if errTempFile != nil {
				cache.err = fmt.Errorf("NewBoltProvider error creating temp file: %w", errTempFile)
				return
			}
			log.Debugf("created temp file: %s", boltDbFile.Name())
			// Close the file; Bolt will open it itself.
			_ = boltDbFile.Close()

			// init bolt with temp file
			viper.Set("db.bolt.file", boltDbFile.Name())
			bp, err := NewBoltProvider()
			if err != nil {
				cache.err = fmt.Errorf("NewBoltProvider: %w", err)
				return
			}
			p = &bp

		default:
			cache.err = fmt.Errorf("unsupported impl: %s", impl)
			return
		}

		if err := p.InitializeDatabase(); err != nil {
			cache.err = fmt.Errorf("InitializeDatabase(%s): %w", impl, err)
			return
		}
		if err := p.CheckAvailability(); err != nil {
			cache.err = fmt.Errorf("CheckAvailability(%s): %w", impl, err)
			return
		}

		cache.p = p
	})

	if cache.err != nil {
		b.Fatalf("failed to init provider %s: %v", impl, cache.err)
	}

	return cache.p
}

// ---------- helpers ----------

func newTestUserBench(id string) *User {
	return &User{
		Enabled:         true,
		Description:     "benchmark user " + id,
		ID:              id,
		Secret:          "supersecret",
		ACLAllowAll:     false,
		ACLAllowedHosts: []string{"git.example.com", "wiki.example.com"},
		DNSNames:        []string{"myhome.no-ip.info"},
		TTLMinutes:      60,
		IPs:             []string{"1.1.1.1"},
	}
}

func newTestACLBench() *ACL {
	ttl := time.Now().Add(1 * time.Hour)
	return &ACL{
		AllowAll:     false,
		AllowedHosts: []string{"git.example.com", "wiki.example.com"},
		TTL:          &ttl,
	}
}

// global counters used by all benchmarks to ensure unique IDs / IPs
var globalUserCounter uint64
var globalIPCounter uint64

func nextUserID(prefix string) string {
	n := atomic.AddUint64(&globalUserCounter, 1)
	return fmt.Sprintf("%s-%d", prefix, n)
}

// nextIPForBench generates a unique, valid IPv4 address in 10.<space>.<y>.<z>
// - space: "namespace" (2nd octet) to avoid collisions between benchmarks
// - each octet is in [1,254] so all IPs are valid and avoid .0/.255
func nextIPForBench(space uint8) string {
	n := atomic.AddUint64(&globalIPCounter, 1)

	s := int(space%254) + 1   // 2nd octet: 1..254
	y := int((n/254)%254) + 1 // 3rd octet: 1..254
	z := int(n%254) + 1       // 4th octet: 1..254

	return fmt.Sprintf("10.%d.%d.%d", s, y, z)
}

// ipForIndex is deterministic and used for prepopulation in GetACL benchmark
func ipForIndex(space uint8, i int) string {
	n := uint64(i + 1)

	s := int(space%254) + 1   // 2nd octet: 1..254
	y := int((n/254)%254) + 1 // 3rd octet: 1..254
	z := int(n%254) + 1       // 4th octet: 1..254

	return fmt.Sprintf("10.%d.%d.%d", s, y, z)
}

// ---------- generic benchmark bodies (implementaion-agnostic) ----------

func benchmarkAddUserParallel(b *testing.B, p Provider) {
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := nextUserID("bench-add-user")
			if err := p.AddUser(newTestUserBench(id)); err != nil {
				b.Fatalf("AddUser(%s): %v", id, err)
			}
		}
	})
}

func benchmarkGetUserParallel(b *testing.B, p Provider) {
	const numUsers = 10_000
	ids := make([]string, numUsers)

	// Prepopulate unique users for this benchmark.
	for i := 0; i < numUsers; i++ {
		id := nextUserID("bench-get-user")
		if err := p.AddUser(newTestUserBench(id)); err != nil {
			b.Fatalf("AddUser(%s): %v", id, err)
		}
		ids[i] = id
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			id := ids[i%numUsers]
			if _, err := p.GetUser(id); err != nil {
				b.Fatalf("GetUser(%s): %v", id, err)
			}
			i++
		}
	})
}

func benchmarkGetAllUsers(b *testing.B, p Provider) {
	const numUsers = 50_000
	for i := 0; i < numUsers; i++ {
		id := nextUserID("bench-all-user")
		if err := p.AddUser(newTestUserBench(id)); err != nil {
			b.Fatalf("AddUser(%s): %v", id, err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := p.GetAllUsers(); err != nil {
			b.Fatalf("GetAllUsers: %v", err)
		}
	}
}

func benchmarkAddIpParallel(b *testing.B, p Provider) {
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ip := nextIPForBench(1) // namespace "1" for this benchmark
			if err := p.AddIp(ip, newTestACLBench()); err != nil {
				b.Fatalf("AddIp(%s): %v", ip, err)
			}
		}
	})
}

func benchmarkGetACLParallel(b *testing.B, p Provider) {
	const numEntries = 10_000
	ips := make([]string, numEntries)

	// Prepopulate IPs for this benchmark (AddIp runs *before* GetACL).
	for i := 0; i < numEntries; i++ {
		ip := ipForIndex(2, i) // namespace "2" so we don't collide with AddIp benchmark IPs
		if err := p.AddIp(ip, newTestACLBench()); err != nil {
			b.Fatalf("AddIp(%s): %v", ip, err)
		}
		ips[i] = ip
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i%numEntries]
			if _, err := p.GetACL(ip); err != nil {
				b.Fatalf("GetACL(%s): %v", ip, err)
			}
			i++
		}
	})
}

// ---------- exported benchmarks (run for each implementation) ----------

var impls = []string{"memory", "bolt"}

// go test -bench=BenchmarkProvider_AddUser_Parallel -benchmem
func BenchmarkProvider_AddUser_Parallel(b *testing.B) {
	for _, impl := range impls {
		impl := impl // shadow for safety in closures
		b.Run(impl, func(b *testing.B) {
			p := getBenchmarkProvider(b, impl)
			benchmarkAddUserParallel(b, p)
		})
	}
}

func BenchmarkProvider_GetUser_Parallel(b *testing.B) {
	for _, impl := range impls {
		impl := impl
		b.Run(impl, func(b *testing.B) {
			p := getBenchmarkProvider(b, impl)
			benchmarkGetUserParallel(b, p)
		})
	}
}

func BenchmarkProvider_GetAllUsers(b *testing.B) {
	for _, impl := range impls {
		impl := impl
		b.Run(impl, func(b *testing.B) {
			p := getBenchmarkProvider(b, impl)
			benchmarkGetAllUsers(b, p)
		})
	}
}

func BenchmarkProvider_AddIp_Parallel(b *testing.B) {
	for _, impl := range impls {
		impl := impl
		b.Run(impl, func(b *testing.B) {
			p := getBenchmarkProvider(b, impl)
			benchmarkAddIpParallel(b, p)
		})
	}
}

func BenchmarkProvider_GetACL_Parallel(b *testing.B) {
	for _, impl := range impls {
		impl := impl
		b.Run(impl, func(b *testing.B) {
			p := getBenchmarkProvider(b, impl)
			benchmarkGetACLParallel(b, p)
		})
	}
}
