package mcauth

import (
	"encoding/json"
	"testing"
	"time"
)

func TestExpiringValue(t *testing.T) {
	fresh := expiring("tok", 60)
	if fresh.IsExpired() || fresh.Get() == nil || *fresh.Get() != "tok" {
		t.Fatal("fresh value should not be expired")
	}
	stale := ExpiringValue[string]{Data: "tok", ExpiresAt: uint64(time.Now().Unix()) - 1}
	if !stale.IsExpired() || stale.Get() != nil {
		t.Fatal("past value should be expired")
	}
}

// The cache shape must round-trip, including the legacy "email" alias.
func TestCachedAccountJSON(t *testing.T) {
	in := `[{"email":"abcd","msa":{"data":{"token_type":"bearer","expires_in":86400,"scope":"service::user.auth.xboxlive.com::MBI_SSL","access_token":"x","refresh_token":"y","user_id":"u"},"expires_at":9999999999},"xbl":{"data":{"token":"x","user_hash":"1"},"expires_at":9999999999},"mca":{"data":{"username":"n","roles":[],"access_token":"x","token_type":"Bearer","expires_in":86400},"expires_at":9999999999},"profile":{"id":"80e18238-bb02-4a77-a3d9-fdd7f6f72f89","name":"abcd","skins":[{"id":"s1","state":"ACTIVE"}],"capes":[]}}]`
	var accounts []CachedAccount
	if err := json.Unmarshal([]byte(in), &accounts); err != nil {
		t.Fatal(err)
	}
	if accounts[0].CacheKey != "abcd" || accounts[0].Profile.Name != "abcd" {
		t.Fatalf("bad decode: %+v", accounts[0])
	}
	out, err := json.Marshal(accounts)
	if err != nil {
		t.Fatal(err)
	}
	var rt []map[string]any
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cache_key", "msa", "xbl", "mca", "profile"} {
		if _, ok := rt[0][key]; !ok {
			t.Fatalf("re-encoded account missing %q: %s", key, out)
		}
	}
}
