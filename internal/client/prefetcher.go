// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// prefetcher.go — Predictive DNS Prefetching (Proactive Resolution)
//
// When a primary domain is seen (via SOCKS5 CONNECT or Local DNS), this module
// looks up a static rule-set of known associated CDN / asset domains and
// dispatches DNS A-record queries for them through the existing ARQ tunnel
// before the browser ever asks. Results land in localDNSCache automatically
// via the normal HandleDNSQueryRes → SetReady path — no extra response handling
// required.
// ==============================================================================

package client

import (
	"context"
	"strings"
	"sync"
	"time"

	dnsCache "masterdnsvpn-go/internal/dnscache"
)

// prefetchRules maps a root-domain key to the list of associated asset/CDN
// domains to pre-resolve. Matching is suffix-based so that subdomains (e.g.
// "www.youtube.com") match the key "youtube.com".
var prefetchRules = map[string][]string{
	"youtube.com":   {"googlevideo.com", "ytimg.com", "ggpht.com", "googleapis.com"},
	"twitter.com":   {"twimg.com", "abs.twimg.com"},
	"x.com":         {"twimg.com", "abs.twimg.com"},
	"instagram.com": {"cdninstagram.com", "fbcdn.net"},
	"facebook.com":  {"fbcdn.net", "fbsbx.com"},
	"reddit.com":    {"redd.it", "redditmedia.com", "redditstatic.com"},
	"netflix.com":   {"nflxvideo.net", "nflximg.net"},
	"twitch.tv":     {"twitchsvc.net", "jtvnw.net", "twitchapps.com"},
	"github.com":    {"githubusercontent.com", "githubassets.com"},
	"google.com":    {"googleapis.com", "gstatic.com", "ggpht.com"},
}

// prefetchSpamTTL is the minimum interval between prefetch dispatches for the
// same domain. Prevents queue flooding when many tabs open the same site.
const prefetchSpamTTL = 30 * time.Second

// triggerPrefetch is called at SOCKS5 CONNECT and Local DNS hook sites.
// It is a no-op when prefetching is disabled or when the incoming domain does
// not match any rule. It is always non-blocking.
func (c *Client) triggerPrefetch(domain string) {
	if !c.prefetchEnabled {
		return
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return
	}

	for ruleKey, targets := range prefetchRules {
		if domain == ruleKey || strings.HasSuffix(domain, "."+ruleKey) {
			for _, target := range targets {
				c.enqueuePrefetch(target)
			}
			return
		}
	}
}

// enqueuePrefetch checks the spam-guard map and, if the domain is not recently
// queued, marks it and pushes it onto the buffered prefetch channel. Drops
// silently if the channel is full — never blocks the caller.
func (c *Client) enqueuePrefetch(domain string) {
	now := time.Now()

	c.prefetchRecentMu.Lock()
	if exp, ok := c.prefetchRecent[domain]; ok && now.Before(exp) {
		c.prefetchRecentMu.Unlock()
		return
	}
	c.prefetchRecent[domain] = now.Add(prefetchSpamTTL)
	c.prefetchRecentMu.Unlock()

	select {
	case c.prefetchQueue <- domain:
	default:
		// Queue full — drop. Better to skip a prefetch than stall real traffic.
	}
}

// prefetchWorker is a long-lived goroutine that drains prefetchQueue and
// resolves each domain through the existing ARQ tunnel. N of these are started
// by StartAsyncRuntime when PredictivePrefetchEnabled is true.
func (c *Client) prefetchWorker(ctx context.Context, id int) {
	defer c.asyncWG.Done()
	c.log.Debugf("Prefetch Worker #%d started", id)

	for {
		select {
		case <-ctx.Done():
			return
		case domain, ok := <-c.prefetchQueue:
			if !ok {
				return
			}
			c.doPrefetch(domain)
		}
	}
}

// doPrefetch resolves a single domain through the tunnel by reusing the full
// existing pipeline:
//  1. LookupOrCreatePending registers interest in the local cache.
//  2. dispatchDNSQueryToTunnel sends the synthetic query via ARQ.
//  3. HandleDNSQueryRes → localDNSCache.SetReady fires automatically when the
//     server responds — no extra code needed here.
func (c *Client) doPrefetch(domain string) {
	const qType = 0x0001  // A record
	const qClass = 0x0001 // IN class

	key := dnsCache.BuildKey(domain, qType, qClass)
	result := c.localDNSCache.LookupOrCreatePending(key, domain, qType, qClass, time.Now())
	if result.Status == dnsCache.StatusReady || !result.DispatchNeeded {
		return // already cached or a real query is already in-flight
	}

	rawQuery := buildDNSAQuery(domain)
	if rawQuery == nil {
		return
	}

	// dispatchDNSQueryToTunnel already nil-guards stream 0 internally.
	c.dispatchDNSQueryToTunnel(rawQuery)
	c.log.Debugf("Prefetch dispatched: %s", domain)
}

// prefetchCleanupWorker periodically removes expired entries from the
// prefetchRecent spam-guard map to prevent unbounded growth.
func (c *Client) prefetchCleanupWorker(ctx context.Context) {
	defer c.asyncWG.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.prefetchRecentMu.Lock()
			for domain, exp := range c.prefetchRecent {
				if now.After(exp) {
					delete(c.prefetchRecent, domain)
				}
			}
			c.prefetchRecentMu.Unlock()
		}
	}
}

// buildDNSAQuery constructs a minimal wire-format DNS A-record query for the
// given domain. Returns nil if any label is invalid.
//
// Wire format:
//
//	Header   (12 bytes): TxID=0x0001, Flags=0x0100 (standard query, RD=1),
//	                     QDCOUNT=1, AN/NS/ARCOUNT=0
//	Question (variable): QNAME labels + 0x00 root + QTYPE(A) + QCLASS(IN)
func buildDNSAQuery(domain string) []byte {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return nil
	}

	// Encode QNAME as length-prefixed labels.
	var qname []byte
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil
		}
		qname = append(qname, byte(len(label)))
		qname = append(qname, label...)
	}
	qname = append(qname, 0x00) // root terminator

	buf := make([]byte, 12+len(qname)+4)
	// Header
	buf[0], buf[1] = 0x00, 0x01 // Transaction ID (arbitrary, zeroed on cache store)
	buf[2], buf[3] = 0x01, 0x00 // Flags: QR=0 (query), RD=1
	buf[4], buf[5] = 0x00, 0x01 // QDCOUNT = 1
	// ANCOUNT, NSCOUNT, ARCOUNT remain 0
	// Question section
	copy(buf[12:], qname)
	off := 12 + len(qname)
	buf[off], buf[off+1] = 0x00, 0x01 // QTYPE  = A
	buf[off+2], buf[off+3] = 0x00, 0x01 // QCLASS = IN
	return buf
}

// prefetchRecentFields groups the spam-guard fields so they can be embedded
// cleanly into Client without cluttering the struct too much.
// (The actual fields live directly on Client — this comment is for reference.)

// prefetchRecentMuType is a convenient alias used only in this file.
type prefetchRecentMuType = sync.Mutex
