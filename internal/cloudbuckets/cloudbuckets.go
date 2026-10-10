// Package cloudbuckets detects cloud object-storage buckets referenced by a
// target's assets and classifies their exposure with read-only requests only.
// It never writes, deletes, or lists-to-download; it fetches the bucket root
// and inspects the response to decide public / protected / dangling.
package cloudbuckets

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Veyselyigit21/Reconixia/internal/safety"
)

// Finding mirrors the host Finding shape so the caller can append it directly.
type Finding struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

type bucket struct {
	provider string
	name     string
	checkURL string
}

var (
	reAWSHost  = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com\b`)
	reAWSPath  = regexp.MustCompile(`(?i)\bs3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\b`)
	reGCSHost  = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com\b`)
	reGCSPath  = regexp.MustCompile(`(?i)\bstorage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\b`)
	reAzure    = regexp.MustCompile(`(?i)\b([a-z0-9]{3,24})\.blob\.core\.windows\.net\b`)
	reDOSpaces = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.([a-z0-9\-]+)\.digitaloceanspaces\.com\b`)
)

// Scan extracts bucket references from the provided string sets and probes each
// unique bucket once. maxBuckets caps how many are checked (0 = default 40).
func Scan(ctx context.Context, timeout time.Duration, maxBuckets int, inputs ...[]string) []Finding {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	if maxBuckets <= 0 {
		maxBuckets = 40
	}
	buckets := extract(inputs...)
	if len(buckets) > maxBuckets {
		buckets = buckets[:maxBuckets]
	}
	client := safety.SafeHTTPClient(timeout)
	out := []Finding{}
	for _, b := range buckets {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		if f, ok := probe(ctx, client, b); ok {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func extract(inputs ...[]string) []bucket {
	seen := map[string]bool{}
	out := []bucket{}
	addAWS := func(name string) {
		name = strings.ToLower(name)
		key := "aws|" + name
		if name == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, bucket{"aws_s3", name, "https://" + name + ".s3.amazonaws.com/"})
	}
	addGCS := func(name string) {
		name = strings.ToLower(name)
		key := "gcs|" + name
		if name == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, bucket{"gcs", name, "https://storage.googleapis.com/" + name + "/"})
	}
	addAzure := func(name string) {
		name = strings.ToLower(name)
		key := "azure|" + name
		if name == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, bucket{"azure_blob", name, "https://" + name + ".blob.core.windows.net/?comp=list"})
	}
	addDO := func(name, region string) {
		name = strings.ToLower(name)
		key := "do|" + name
		if name == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, bucket{"do_spaces", name, "https://" + name + "." + strings.ToLower(region) + ".digitaloceanspaces.com/"})
	}
	for _, set := range inputs {
		for _, s := range set {
			for _, m := range reAWSHost.FindAllStringSubmatch(s, -1) {
				addAWS(m[1])
			}
			for _, m := range reAWSPath.FindAllStringSubmatch(s, -1) {
				addAWS(m[1])
			}
			for _, m := range reGCSHost.FindAllStringSubmatch(s, -1) {
				addGCS(m[1])
			}
			for _, m := range reGCSPath.FindAllStringSubmatch(s, -1) {
				addGCS(m[1])
			}
			for _, m := range reAzure.FindAllStringSubmatch(s, -1) {
				addAzure(m[1])
			}
			for _, m := range reDOSpaces.FindAllStringSubmatch(s, -1) {
				addDO(m[1], m[2])
			}
		}
	}
	return out
}

func probe(ctx context.Context, client *http.Client, b bucket) (Finding, bool) {
	if !safety.IsSafeFetchURL(b.checkURL) {
		return Finding{}, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.checkURL, nil)
	if err != nil {
		return Finding{}, false
	}
	req.Header.Set("User-Agent", "Reconixia/1.0 AuthorizedResearch")
	resp, err := client.Do(req)
	if err != nil {
		return Finding{}, false
	}
	defer resp.Body.Close()
	body := ""
	if resp.Body != nil {
		b2, _ := io.ReadAll(io.LimitReader(resp.Body, 32_000))
		body = string(b2)
	}
	lower := strings.ToLower(body)
	status := resp.StatusCode

	switch {
	case status == 200 && (strings.Contains(lower, "<listbucketresult") ||
		strings.Contains(lower, "<enumerationresults") ||
		strings.Contains(lower, "\"items\"") && b.provider == "gcs"):
		return Finding{
			Type:       "cloud_bucket_public_listing",
			URL:        b.checkURL,
			Status:     status,
			Confidence: "high",
			Note:       b.provider + " bucket `" + b.name + "` listing is publicly readable; review for sensitive objects (read-only, do not exfiltrate)",
		}, true
	case status == 404 && (strings.Contains(lower, "nosuchbucket") || strings.Contains(lower, "the specified bucket does not exist")):
		return Finding{
			Type:       "cloud_bucket_dangling",
			URL:        b.checkURL,
			Status:     status,
			Confidence: "medium",
			Note:       b.provider + " bucket `" + b.name + "` is referenced but does not exist; possible bucket-takeover candidate, verify ownership rules",
		}, true
	case status == 403 || strings.Contains(lower, "accessdenied") || strings.Contains(lower, "authenticationrequired"):
		return Finding{
			Type:       "cloud_bucket_protected",
			URL:        b.checkURL,
			Status:     status,
			Confidence: "info",
			Note:       b.provider + " bucket `" + b.name + "` exists but denies anonymous listing; no exposure from recon alone",
		}, true
	}
	return Finding{}, false
}
