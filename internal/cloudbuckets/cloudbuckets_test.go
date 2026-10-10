package cloudbuckets

import "testing"

func TestExtractFindsBucketsAcrossProviders(t *testing.T) {
	inputs := [][]string{{
		`<script src="https://assets-prod.s3.amazonaws.com/app.js"></script>`,
		`https://s3.eu-west-1.amazonaws.com/legacy-backups/dump.sql`,
		`url(https://cdn-media.storage.googleapis.com/logo.png)`,
		`https://storage.googleapis.com/public-reports/q1.pdf`,
		`https://companydata.blob.core.windows.net/container/file`,
		`https://space-assets.fra1.digitaloceanspaces.com/img.png`,
		`nothing-here-to-match`,
	}}
	buckets := extract(inputs...)
	want := map[string]bool{
		"assets-prod":    false,
		"legacy-backups": false,
		"cdn-media":      false,
		"public-reports": false,
		"companydata":    false,
		"space-assets":   false,
	}
	for _, b := range buckets {
		if _, ok := want[b.name]; ok {
			want[b.name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("bucket bulunamadı: %s", name)
		}
	}
}

func TestExtractDeduplicates(t *testing.T) {
	inputs := [][]string{{
		`https://dupe.s3.amazonaws.com/a`,
		`https://dupe.s3.amazonaws.com/b`,
	}}
	if n := len(extract(inputs...)); n != 1 {
		t.Fatalf("tekilleştirme beklendi, %d bucket döndü", n)
	}
}
