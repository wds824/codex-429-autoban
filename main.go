// Package main implements the codex-429-autoban CPA plugin.
//
// It auto-disables a Codex credential after a 429 and auto-re-enables it
// once the rate-limit window that was hit has refreshed.
//
// Three capabilities are registered:
//   - usage_plugin: observes every completed request. On a Codex 429 it reads
//     the upstream x-codex-* response headers, decides whether the 5-hour
//     window or the weekly cap was exhausted, and records the exact reset
//     time at which the credential may be used again.
//   - scheduler: on every credential pick, it drops candidates whose recorded
//     reset time has not yet passed (lazy re-enable, since CPA exposes no
//     timer hook) and delegates the actual selection to the built-in
//     round-robin scheduler.
//   - management_api: exposes a small status page and authenticated API for
//     manually clearing the in-memory ban state after the user resets Codex
//     quota or uses a reset card upstream.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"codex-429-autoban/cpasdk/pluginabi"
	"codex-429-autoban/cpasdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	pluginName    = "codex-429-autoban"
	pluginVersion = "0.3.3"

	// providerCodex is the CPA provider key for OpenAI Codex (ChatGPT backend).
	providerCodex = "codex"

	// statusTooManyRequests is the HTTP 429 status code.
	statusTooManyRequests = 429

	// Codex rate-limit window sizes, in minutes, as reported by the
	// x-codex-primary-window-minutes / x-codex-secondary-window-minutes
	// response headers.
	windowMinutes5h       = 300   // 5 hours
	windowMinutesWeek     = 10080 // 7 days
	windowMinutesMonthMin = 40320 // 4 weeks; month-sized windows may be 28-31 days

	// usedPercentThreshold is the "this window is the one that tripped" marker.
	// A 429 carries the window that exhausted at ~100% used.
	usedPercentThreshold = 100

	managementRoutePrefix = "/plugins/" + pluginName
	discordWebhookTitle   = "Codex 429 Autoban"
)

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type pluginConfig struct {
	DiscordWebhookURL string `yaml:"discord_webhook_url"`
	DiscordMention    string `yaml:"discord_mention"`
	DiscordNotify429  bool   `yaml:"discord_notify_429"`
	DiscordNotifyPool bool   `yaml:"discord_notify_pool"`
}

type configState struct {
	mu         sync.RWMutex
	cfg        pluginConfig
	configured bool
}

var runtimeConfigState configState

// banStore holds, per credential, the time at which it may be used again.
// A credential is absent from the map when it is not currently banned.
// This is in-process memory; CPA plugins are long-lived and loaded once, so
// state persists across requests. It does not survive a CPA restart, which is
// acceptable because a restart also clears CPA's own cooldown state.
var banStore banState

type banState struct {
	mu   sync.Mutex
	bans map[string]banEntry // keyed by AuthID
}

type banEntry struct {
	// ResetAt is the upstream-reported time at which the exhausted window
	// refreshes. The credential is skipped until now >= ResetAt.
	ResetAt time.Time
	// Window is a human-readable label of which limit was hit ("5h", "week", or "month").
	Window string
	// BannedAt is when the ban was recorded, for logging only.
	BannedAt time.Time
}

// lookup returns the ban entry for the given auth ID and whether one exists.
func (s *banState) lookup(authID string) (banEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.bans[authID]
	return e, ok
}

// set records a ban for the given auth ID.
func (s *banState) set(authID string, e banEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bans == nil {
		s.bans = make(map[string]banEntry)
	}
	s.bans[authID] = e
}

// clearIfExpired removes the ban for authID if its reset time has passed.
// Returns whether the credential is currently banned AFTER this check.
func (s *banState) clearIfExpired(authID string, now time.Time) (stillBanned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.bans[authID]
	if !ok {
		return false
	}
	if !now.Before(e.ResetAt) {
		// Reset time has passed: auto re-enable.
		delete(s.bans, authID)
		slog.Info("codex-429-autoban: auto re-enabled credential",
			"auth_id", authID, "window", e.Window, "reset_at", e.ResetAt.Format(time.RFC3339))
		return false
	}
	return true
}

// clearExpired removes every ban whose reset time has passed.
func (s *banState) clearExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for authID, e := range s.bans {
		if !now.Before(e.ResetAt) {
			delete(s.bans, authID)
			removed++
			slog.Info("codex-429-autoban: auto re-enabled credential",
				"auth_id", authID, "window", e.Window, "reset_at", e.ResetAt.Format(time.RFC3339))
		}
	}
	return removed
}

// clear removes the ban for authID, if present.
func (s *banState) clear(authID string) (banEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bans == nil {
		return banEntry{}, false
	}
	e, ok := s.bans[authID]
	if ok {
		delete(s.bans, authID)
	}
	return e, ok
}

// clearAll removes every active ban and returns how many were removed.
func (s *banState) clearAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.bans)
	s.bans = make(map[string]banEntry)
	return n
}

// snapshot returns a copy of the current bans for diagnostics / management UI.
func (s *banState) snapshot() map[string]banEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]banEntry, len(s.bans))
	for authID, e := range s.bans {
		out[authID] = e
	}
	return out
}

func main() {}

// cliproxy_plugin_init is the native entry point CPA calls when loading the
// plugin. It wires the host reverse-call API and registers our call/free/shutdown
// function pointers.
//
//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

// cliproxyPluginCall is the single dispatch entry CPA invokes for every method.
//
//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	C.store_host_api(nil)
}

// handleMethod routes a CPA method to its handler.
func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configurePlugin(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodUsageHandle:
		return handleUsage(request)
	case pluginabi.MethodSchedulerPick:
		return handleSchedulerPick(request)
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration())
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

// pluginRegistration declares the plugin's metadata and capabilities.
// Both usage_plugin and scheduler must be true.
func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "wds824",
			GitHubRepository: "https://github.com/wds824/codex-429-autoban",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "discord_webhook_url",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Discord incoming webhook URL. Leave empty to disable Discord notifications.",
				},
				{
					Name:        "discord_mention",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Optional Discord mention for alerts, e.g. <@USER_ID>, <@&ROLE_ID>, @everyone, or @here.",
				},
				{
					Name:        "discord_notify_429",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Send a Discord notification when a Codex account is newly excluded after a 429.",
				},
				{
					Name:        "discord_notify_pool",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Include current Codex available/total pool counts in Discord notifications.",
				},
			},
		},
		Capabilities: registrationCapability{
			UsagePlugin:   true,
			Scheduler:     true,
			ManagementAPI: true,
		},
	}
}

func defaultPluginConfig() pluginConfig {
	return pluginConfig{
		DiscordNotify429:  true,
		DiscordNotifyPool: true,
	}
}

func configurePlugin(raw []byte) error {
	cfg := defaultPluginConfig()
	if len(raw) > 0 {
		var req lifecycleRequest
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return fmt.Errorf("decode plugin lifecycle request: %w", errUnmarshal)
		}
		if len(req.ConfigYAML) > 0 {
			if errDecode := yaml.Unmarshal(req.ConfigYAML, &cfg); errDecode != nil {
				return fmt.Errorf("decode plugin config: %w", errDecode)
			}
		}
	}
	cfg.DiscordWebhookURL = strings.TrimSpace(cfg.DiscordWebhookURL)
	cfg.DiscordMention = strings.TrimSpace(cfg.DiscordMention)
	if cfg.DiscordWebhookURL != "" {
		parsed, errParse := url.Parse(cfg.DiscordWebhookURL)
		if errParse != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("discord_webhook_url must be an http(s) URL")
		}
	}
	if _, _, errMention := discordMentionParts(cfg.DiscordMention); errMention != nil {
		return errMention
	}
	runtimeConfigState.mu.Lock()
	runtimeConfigState.cfg = cfg
	runtimeConfigState.configured = true
	runtimeConfigState.mu.Unlock()
	if cfg.DiscordWebhookURL == "" {
		slog.Info("codex-429-autoban: Discord webhook notifications disabled")
	} else {
		slog.Info("codex-429-autoban: Discord webhook notifications configured",
			"notify_429", cfg.DiscordNotify429, "notify_pool", cfg.DiscordNotifyPool)
	}
	return nil
}

func configuredPlugin() pluginConfig {
	runtimeConfigState.mu.RLock()
	cfg := runtimeConfigState.cfg
	configured := runtimeConfigState.configured
	runtimeConfigState.mu.RUnlock()
	if !configured {
		return defaultPluginConfig()
	}
	return cfg
}

// handleUsage observes a completed request. On a Codex 429 it records the
// ban; otherwise it is a no-op.
func handleUsage(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return okEnvelope(map[string]any{})
	}
	var record pluginapi.UsageRecord
	if errUnmarshal := json.Unmarshal(raw, &record); errUnmarshal != nil {
		slog.Warn("codex-429-autoban: failed to decode usage record", "error", errUnmarshal)
		return okEnvelope(map[string]any{})
	}

	// Only Codex credentials are in scope.
	if !strings.EqualFold(record.Provider, providerCodex) {
		return okEnvelope(map[string]any{})
	}
	// Only act on 429 failures.
	if !record.Failed || record.Failure.StatusCode != statusTooManyRequests {
		return okEnvelope(map[string]any{})
	}
	authID := strings.TrimSpace(record.AuthID)
	if authID == "" {
		slog.Warn("codex-429-autoban: 429 received but AuthID is empty, cannot ban")
		return okEnvelope(map[string]any{})
	}

	now := time.Now()
	previous, hadPrevious := banStore.lookup(authID)
	wasActive := hadPrevious && now.Before(previous.ResetAt)
	entry, ok := classifyAndBuildBan(record.ResponseHeaders)
	if !ok {
		// Could not determine which window was hit from the headers.
		// Fall back to a conservative 5-hour ban so the credential is not
		// hammered while rate-limited, matching the more common case.
		entry = banEntry{
			ResetAt:  now.Add(5 * time.Hour),
			Window:   "5h (fallback, headers missing)",
			BannedAt: now,
		}
		slog.Warn("codex-429-autoban: x-codex-* headers missing on 429, falling back to 5h ban",
			"auth_id", authID)
	} else {
		entry.BannedAt = now
	}

	banStore.set(authID, entry)
	slog.Info("codex-429-autoban: banned credential after 429",
		"auth_id", authID,
		"window", entry.Window,
		"reset_at", entry.ResetAt.Format(time.RFC3339))
	if !wasActive {
		sendDiscord429Notification(record, entry)
	}
	return okEnvelope(map[string]any{})
}

type hostAuthListResponse struct {
	Files []pluginapi.HostAuthFileEntry `json:"files"`
}

func hostAuthEntries() ([]pluginapi.HostAuthFileEntry, error) {
	raw, errHost := callHost(pluginabi.MethodHostAuthList, map[string]any{})
	if errHost != nil {
		return nil, errHost
	}
	var response hostAuthListResponse
	if errUnmarshal := json.Unmarshal(raw, &response); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host.auth.list result: %w", errUnmarshal)
	}
	return response.Files, nil
}

func findHostAuthEntry(entries []pluginapi.HostAuthFileEntry, authID string) (pluginapi.HostAuthFileEntry, bool) {
	for _, auth := range entries {
		if authIDMatches(authID, auth.ID, auth.AuthIndex, auth.Name, auth.Path) {
			return auth, true
		}
	}
	return pluginapi.HostAuthFileEntry{}, false
}

type poolStats struct {
	Available    int
	Total        int
	Known        bool
	CandidateIDs map[string]struct{}
}

type poolStatsState struct {
	mu    sync.RWMutex
	stats poolStats
}

var latestPoolStats poolStatsState

func sendDiscord429Notification(record pluginapi.UsageRecord, entry banEntry) {
	cfg := configuredPlugin()
	if cfg.DiscordWebhookURL == "" || !cfg.DiscordNotify429 {
		return
	}

	stats := currentCodexPoolStats(record.AuthID)
	poolText := "未知"
	if stats.Known {
		poolText = fmt.Sprintf("%d / %d", stats.Available, stats.Total)
	}
	resetUnix := entry.ResetAt.Unix()
	resetText := entry.ResetAt.Format(time.RFC3339) + " (<t:" + strconv.FormatInt(resetUnix, 10) + ":R>)"
	fields := []discordField{
		{Name: "账号", Value: discordCode(record.AuthID), Inline: false},
		{Name: "窗口", Value: entry.Window, Inline: true},
		{Name: "解除时间", Value: resetText, Inline: true},
	}
	if cfg.DiscordNotifyPool {
		fields = append(fields, discordField{Name: "Codex 号池可用 / 总数", Value: poolText, Inline: true})
	}
	payload := discordWebhookPayload{
		Username: discordWebhookTitle,
		Embeds: []discordEmbed{{
			Title:     "Codex 账号已因 429 移出号池",
			Color:     15158332,
			Fields:    fields,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Footer:    discordFooter{Text: pluginName + " v" + pluginVersion},
		}},
	}
	if errMention := addDiscordMention(&payload, cfg.DiscordMention); errMention != nil {
		slog.Warn("codex-429-autoban: invalid Discord mention, skipping webhook notification", "error", errMention)
		return
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		slog.Warn("codex-429-autoban: failed to encode Discord webhook payload", "error", errMarshal)
		return
	}
	go func() {
		if errPost := postDiscordWebhook(cfg.DiscordWebhookURL, raw); errPost != nil {
			slog.Warn("codex-429-autoban: Discord webhook request failed", "error", errPost)
		}
	}()
}

type discordWebhookPayload struct {
	Username         string                  `json:"username,omitempty"`
	Content          string                  `json:"content,omitempty"`
	AllowedMentions  *discordAllowedMentions `json:"allowed_mentions,omitempty"`
	Embeds           []discordEmbed          `json:"embeds,omitempty"`
}

type discordAllowedMentions struct {
	Parse  []string `json:"parse"`
	Users  []string `json:"users,omitempty"`
	Roles  []string `json:"roles,omitempty"`
}

type discordEmbed struct {
	Title     string         `json:"title,omitempty"`
	Color     int            `json:"color,omitempty"`
	Fields    []discordField `json:"fields,omitempty"`
	Timestamp string         `json:"timestamp,omitempty"`
	Footer    discordFooter  `json:"footer,omitempty"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordFooter struct {
	Text string `json:"text,omitempty"`
}

func discordCode(value string) string {
	return "`" + strings.ReplaceAll(strings.TrimSpace(value), "`", "'") + "`"
}

func addDiscordMention(payload *discordWebhookPayload, raw string) error {
	mention, allowed, errMention := discordMentionParts(raw)
	if errMention != nil {
		return errMention
	}
	if mention == "" {
		return nil
	}
	payload.Content = mention + " Codex 429 告警"
	payload.AllowedMentions = allowed
	return nil
}

func discordMentionParts(raw string) (string, *discordAllowedMentions, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil, nil
	}
	if raw == "@everyone" || raw == "@here" {
		return raw, &discordAllowedMentions{Parse: []string{"everyone"}}, nil
	}
	if strings.HasPrefix(raw, "<@&") && strings.HasSuffix(raw, ">") {
		id := strings.TrimSuffix(strings.TrimPrefix(raw, "<@&"), ">")
		if isDiscordSnowflake(id) {
			return raw, &discordAllowedMentions{Parse: []string{}, Roles: []string{id}}, nil
		}
		return "", nil, fmt.Errorf("discord_mention has invalid role mention %q", raw)
	}
	if strings.HasPrefix(raw, "<@") && strings.HasSuffix(raw, ">") {
		id := strings.TrimSuffix(strings.TrimPrefix(raw, "<@"), ">")
		id = strings.TrimPrefix(id, "!")
		if isDiscordSnowflake(id) {
			return raw, &discordAllowedMentions{Parse: []string{}, Users: []string{id}}, nil
		}
		return "", nil, fmt.Errorf("discord_mention has invalid user mention %q", raw)
	}
	return "", nil, fmt.Errorf("discord_mention must be <@USER_ID>, <@&ROLE_ID>, @everyone, or @here")
}

func isDiscordSnowflake(value string) bool {
	if value == "" || len(value) > 25 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func postDiscordWebhook(webhookURL string, payload []byte) error {
	request, errNewRequest := http.NewRequest(http.MethodPost, webhookURL, strings.NewReader(string(payload)))
	if errNewRequest != nil {
		return fmt.Errorf("create request: %w", errNewRequest)
	}
	request.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 10 * time.Second}
	response, errDo := client.Do(request)
	if errDo != nil {
		return fmt.Errorf("send request: %w", errDo)
	}
	response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("Discord returned HTTP %d", response.StatusCode)
	}
	return nil
}

func currentCodexPoolStats(recentAuthID string) poolStats {
	if stats, errHost := hostCodexPoolStats(recentAuthID); errHost == nil {
		return stats
	} else {
		slog.Debug("codex-429-autoban: unable to read auth list for Discord pool status", "error", errHost)
	}

	stats := latestPoolStats.snapshot()
	if !stats.Known {
		return stats
	}
	if _, candidateSeen := stats.CandidateIDs[strings.TrimSpace(recentAuthID)]; candidateSeen && stats.Available > 0 {
		stats.Available--
	}
	return stats
}

func hostCodexPoolStats(recentAuthID string) (poolStats, error) {
	entries, errHost := hostAuthEntries()
	if errHost != nil {
		return poolStats{}, errHost
	}

	now := time.Now()
	stats := poolStats{Known: true, CandidateIDs: make(map[string]struct{})}
	for _, auth := range entries {
		if !strings.EqualFold(strings.TrimSpace(auth.Provider), providerCodex) {
			continue
		}
		stats.Total++
		for _, id := range []string{auth.ID, auth.Name, auth.Path} {
			if id = strings.TrimSpace(id); id != "" {
				stats.CandidateIDs[id] = struct{}{}
			}
		}
		if auth.Disabled || auth.Unavailable || strings.EqualFold(auth.Status, "disabled") || strings.EqualFold(auth.Status, "unavailable") {
			continue
		}
		if !auth.NextRetryAfter.IsZero() && now.Before(auth.NextRetryAfter) {
			continue
		}
		if authIDMatches(recentAuthID, auth.ID, auth.Name, auth.Path) || authIsBanned(auth.ID, auth.Name, auth.Path) {
			continue
		}
		stats.Available++
	}
	return stats, nil
}

func authIDMatches(target string, ids ...string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, id := range ids {
		if target == strings.TrimSpace(id) {
			return true
		}
	}
	return false
}

func authIsBanned(ids ...string) bool {
	now := time.Now()
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			continue
		}
		entry, ok := banStore.lookup(strings.TrimSpace(id))
		if ok && now.Before(entry.ResetAt) {
			return true
		}
	}
	return false
}

func (s *poolStatsState) set(stats poolStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stats.CandidateIDs == nil {
		stats.CandidateIDs = make(map[string]struct{})
	}
	s.stats = stats
}

func (s *poolStatsState) snapshot() poolStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stats := s.stats
	stats.CandidateIDs = make(map[string]struct{}, len(s.stats.CandidateIDs))
	for id := range s.stats.CandidateIDs {
		stats.CandidateIDs[id] = struct{}{}
	}
	return stats
}

func callHost(method string, payload any) (json.RawMessage, error) {
	rawPayload, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return nil, fmt.Errorf("marshal host callback payload %s: %w", method, errMarshal)
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))

	var response C.cliproxy_buffer
	var requestPtr *C.uint8_t
	if len(rawPayload) > 0 {
		cPayload := C.CBytes(rawPayload)
		if cPayload == nil {
			return nil, fmt.Errorf("allocate host callback payload %s", method)
		}
		defer C.free(cPayload)
		requestPtr = (*C.uint8_t)(cPayload)
	}
	callCode := C.call_host_api(cMethod, requestPtr, C.size_t(len(rawPayload)), &response)
	var rawResponse []byte
	if response.ptr != nil && response.len > 0 {
		rawResponse = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.free_host_buffer(response.ptr, response.len)
	}
	if len(rawResponse) == 0 {
		return nil, fmt.Errorf("host callback %s returned no response, code=%d", method, int(callCode))
	}

	var env envelope
	if errUnmarshal := json.Unmarshal(rawResponse, &env); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host callback envelope %s: %w", method, errUnmarshal)
	}
	if !env.OK {
		if env.Error != nil {
			return nil, fmt.Errorf("%s: %s", env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("host callback %s failed", method)
	}
	if callCode != 0 {
		return nil, fmt.Errorf("host callback %s returned code=%d", method, int(callCode))
	}
	return append(json.RawMessage(nil), env.Result...), nil
}

// classifyAndBuildBan inspects the upstream x-codex-* response headers and
// decides which rate-limit window was exhausted, returning the ban entry with
// the corresponding reset time. Returns ok=false when the headers are absent
// or inconclusive.
//
// Header reference (ChatGPT/Codex backend, not the public Platform API):
//   - x-codex-primary-window-minutes   = 300 for 5h, ~43200 for a 30-day window
//   - x-codex-primary-reset-at         = Unix seconds, primary window reset
//   - x-codex-primary-used-percent     = 0-100
//   - x-codex-secondary-window-minutes = 10080 for the weekly window
//   - x-codex-secondary-reset-at       = Unix seconds, weekly window reset
//   - x-codex-secondary-used-percent   = 0-100
func classifyAndBuildBan(headers http.Header) (banEntry, bool) {
	h := headers

	primaryUsed := headerFloat(h, "x-codex-primary-used-percent")
	secondaryUsed := headerFloat(h, "x-codex-secondary-used-percent")
	primaryWindowMinutes := headerInt(h, "x-codex-primary-window-minutes")
	primaryReset := headerUnixTime(h, "x-codex-primary-reset-at")
	secondaryReset := headerUnixTime(h, "x-codex-secondary-reset-at")

	// Prefer the explicit "which window is full" signal: the window whose
	// used-percent reached the threshold. If both are present, pick the one
	// at threshold; if only one header family is present, use that.
	primaryFull := primaryUsed >= usedPercentThreshold
	secondaryFull := secondaryUsed >= usedPercentThreshold

	switch {
	case secondaryFull && !primaryFull:
		if !secondaryReset.IsZero() {
			return banEntry{ResetAt: secondaryReset, Window: "week"}, true
		}
	case primaryFull && !secondaryFull:
		if !primaryReset.IsZero() {
			return banEntry{ResetAt: primaryReset, Window: primaryWindowLabel(primaryWindowMinutes, secondaryReset.IsZero())}, true
		}
	case primaryFull && secondaryFull:
		// Both exhausted: must wait for the later reset (weekly) to be safe.
		if !secondaryReset.IsZero() {
			return banEntry{ResetAt: secondaryReset, Window: "week (both full)"}, true
		}
		if !primaryReset.IsZero() {
			return banEntry{ResetAt: primaryReset, Window: primaryWindowLabel(primaryWindowMinutes, false) + " (both full, secondary reset missing)"}, true
		}
	default:
		// A monthly account can expose only one window. When there is no usable
		// secondary reset time, the primary reset-at is authoritative regardless
		// of used-percent; use it to return the credential to the pool.
		if !primaryReset.IsZero() && secondaryReset.IsZero() {
			return banEntry{ResetAt: primaryReset, Window: primaryWindowLabel(primaryWindowMinutes, true)}, true
		}

		// With two windows present, use the known window size when the usage
		// percentages are not decisive.
		if !primaryReset.IsZero() && primaryWindowMinutes == windowMinutes5h {
			return banEntry{ResetAt: primaryReset, Window: "5h"}, true
		}
		if !secondaryReset.IsZero() && headerInt(h, "x-codex-secondary-window-minutes") == windowMinutesWeek {
			return banEntry{ResetAt: secondaryReset, Window: "week"}, true
		}
	}
	return banEntry{}, false
}

// primaryWindowLabel identifies the primary window. A primary-only response is
// the monthly-account shape: its reset timestamp is authoritative and is
// presented as month even if the provider's window-minutes field is absent or
// still carries the default primary value. For explicit durations, four weeks
// is the lower bound used for the month label.
func primaryWindowLabel(windowMinutes int, singleWindow bool) string {
	if singleWindow {
		return "month"
	}
	switch {
	case windowMinutes == windowMinutes5h:
		return "5h"
	case windowMinutes == windowMinutesWeek:
		return "week"
	case windowMinutes >= windowMinutesMonthMin:
		return "month"
	case windowMinutes > 0:
		return "primary (" + strconv.Itoa(windowMinutes) + "m)"
	default:
		return "single window"
	}
}

// handleSchedulerPick filters out credentials that are still banned, then
// delegates the actual selection to the built-in round-robin scheduler.
func handleSchedulerPick(raw []byte) ([]byte, error) {
	var req pluginapi.SchedulerPickRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	now := time.Now()
	available := make([]pluginapi.SchedulerAuthCandidate, 0, len(req.Candidates))
	codexTotal := 0
	codexAvailable := 0
	candidateIDs := make(map[string]struct{})
	for _, candidate := range req.Candidates {
		// Only Codex credentials are subject to our bans.
		if !strings.EqualFold(candidate.Provider, providerCodex) {
			available = append(available, candidate)
			continue
		}
		codexTotal++
		candidateIDs[candidate.ID] = struct{}{}
		// clearIfExpired auto-re-enables credentials whose reset time passed.
		if banStore.clearIfExpired(candidate.ID, now) {
			// Still banned: drop from the candidate list.
			continue
		}
		codexAvailable++
		available = append(available, candidate)
	}
	latestPoolStats.set(poolStats{
		Available:    codexAvailable,
		Total:        codexTotal,
		Known:        true,
		CandidateIDs: candidateIDs,
	})

	// If every Codex candidate is banned (and there were no non-Codex ones),
	// decline to handle so CPA's own logic can decide (e.g. wait on its
	// built-in cooldown, or return an error). We do not force a pick here.
	if len(available) == 0 {
		return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}

	// CPA applies our response as follows (conductor.go):
	//   - if AuthID is set and matches a candidate  -> use exactly that one
	//   - else if DelegateBuiltin is set            -> run the built-in
	//                                                   scheduler over the FULL
	//                                                   candidate set (it cannot
	//                                                   be shrunk by the plugin)
	//   - else (Handled false)                      -> host falls back to its
	//                                                   own built-in scheduler
	//
	// Because DelegateBuiltin would let round-robin pick a banned credential,
	// when anything is banned we pick an available AuthID ourselves. When
	// nothing is banned we delegate to round-robin to preserve normal
	// load-balancing.
	if len(available) == len(req.Candidates) {
		return okEnvelope(pluginapi.SchedulerPickResponse{
			DelegateBuiltin: pluginapi.SchedulerBuiltinRoundRobin,
			Handled:         true,
		})
	}
	// Pick the available candidate with the highest numeric priority value
	// (CPA's convention: higher priority value = higher precedence).
	chosen := available[0]
	for _, c := range available[1:] {
		if c.Priority > chosen.Priority {
			chosen = c
		}
	}
	return okEnvelope(pluginapi.SchedulerPickResponse{
		AuthID:  chosen.ID,
		Handled: true,
	})
}

// managementRegistration exposes a small Management API and resource page so
// users can put an auth back into the pool after manually resetting Codex
// quota or using a reset card. CPA does not provide a timer/event for that
// upstream-side action, so manual unban is the reliable integration point.
func managementRegistration() pluginapi.ManagementRegistrationResponse {
	return pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{
				Method:      http.MethodGet,
				Path:        managementRoutePrefix + "/bans",
				Description: "List Codex auths currently held out of the pool by codex-429-autoban.",
			},
			{
				Method:      http.MethodPost,
				Path:        managementRoutePrefix + "/unban",
				Description: "Remove one Codex auth from the in-memory ban list. Body: {\"auth_id\":\"...\"}.",
			},
			{
				Method:      http.MethodPost,
				Path:        managementRoutePrefix + "/reset-ban",
				Description: "Re-apply one Codex auth ban until the effective reset time shown by the status page. Body: {\"auth_id\":\"...\"}.",
			},
			{
				Method:      http.MethodPost,
				Path:        managementRoutePrefix + "/unban-all",
				Description: "Remove every Codex auth from the in-memory ban list.",
			},
			{
				Method:      http.MethodPost,
				Path:        managementRoutePrefix + "/test-webhook",
				Description: "Send a test notification to the configured Discord webhook.",
			},
		},
		Resources: []pluginapi.ResourceRoute{
			{
				Path:        "/status",
				Menu:        "Codex 429 Autoban",
				Description: "View and manually unban Codex credentials after a quota reset.",
			},
		},
	}
}

func handleManagement(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return okEnvelope(dispatchManagement(req))
}

func dispatchManagement(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	switch {
	case method == http.MethodGet && matchesManagementPath(req.Path, "/bans"):
		return jsonManagementResponse(http.StatusOK, currentBanStatus())
	case method == http.MethodPost && matchesManagementPath(req.Path, "/unban"):
		return handleManagementUnban(req)
	case method == http.MethodPost && matchesManagementPath(req.Path, "/reset-ban"):
		return handleManagementResetBan(req)
	case method == http.MethodPost && matchesManagementPath(req.Path, "/unban-all"):
		return handleManagementUnbanAll()
	case method == http.MethodPost && matchesManagementPath(req.Path, "/test-webhook"):
		return handleManagementTestWebhook()
	case method == http.MethodGet && matchesResourcePath(req.Path, "/status"):
		return htmlManagementResponse(http.StatusOK, managementStatusPage())
	default:
		return jsonManagementResponse(http.StatusNotFound, map[string]any{
			"error":  "not_found",
			"path":   req.Path,
			"method": method,
		})
	}
}

type managementBanStatus struct {
	Plugin              string              `json:"plugin"`
	Version             string              `json:"version"`
	Count               int                 `json:"count"`
	CPAAuthListAvailable bool                `json:"cpa_auth_list_available"`
	CPAAuthListError     string              `json:"cpa_auth_list_error,omitempty"`
	Bans                []managementBanInfo `json:"bans"`
}

type managementBanInfo struct {
	AuthID                    string `json:"auth_id"`
	Window                    string `json:"window"`
	BannedAt                  string `json:"banned_at,omitempty"`
	BannedAtUnix               int64  `json:"banned_at_unix,omitempty"`
	ResetAt                   string `json:"reset_at"`
	ResetAtUnix               int64  `json:"reset_at_unix"`
	RemainingSeconds          int64  `json:"remaining_seconds"`
	CPAAuthFound              bool   `json:"cpa_auth_found"`
	CPANextRetryAfter         string `json:"cpa_next_retry_after,omitempty"`
	CPANextRetryAfterUnix     int64  `json:"cpa_next_retry_after_unix,omitempty"`
	CPAStatus                 string `json:"cpa_status,omitempty"`
	CPAStatusMessage          string `json:"cpa_status_message,omitempty"`
	CPAUnavailable             bool   `json:"cpa_unavailable,omitempty"`
	EffectiveResetAt          string `json:"effective_reset_at"`
	EffectiveResetAtUnix      int64  `json:"effective_reset_at_unix"`
	EffectiveRemainingSeconds int64  `json:"effective_remaining_seconds"`
	EffectiveResetSource      string `json:"effective_reset_source"`
}

func currentBanStatus() managementBanStatus {
	now := time.Now()
	banStore.clearExpired(now)
	snapshot := banStore.snapshot()
	entries, errHost := hostAuthEntries()
	status := managementBanStatus{
		Plugin:               pluginName,
		Version:              pluginVersion,
		CPAAuthListAvailable: errHost == nil,
	}
	if errHost != nil {
		status.CPAAuthListError = errHost.Error()
		slog.Debug("codex-429-autoban: unable to read CPA auth list for management status", "error", errHost)
	}
	bans := make([]managementBanInfo, 0, len(snapshot))
	for authID, entry := range snapshot {
		cpaAuth, cpaFound := findHostAuthEntry(entries, authID)
		effectiveResetAt := entry.ResetAt
		effectiveResetSource := "plugin"
		if cpaFound && !cpaAuth.NextRetryAfter.IsZero() {
			if cpaAuth.NextRetryAfter.After(effectiveResetAt) {
				effectiveResetAt = cpaAuth.NextRetryAfter
				effectiveResetSource = "cpa"
			} else {
				effectiveResetSource = "plugin_and_cpa"
			}
		} else if cpaFound && cpaAuth.Unavailable {
			// CPA reports this auth as unavailable but did not provide a
			// timestamp. The plugin reset remains the lower bound only;
			// the actual CPA return time is unknown.
			effectiveResetSource = "unknown"
		}

		remaining := remainingSeconds(now, entry.ResetAt)
		effectiveRemaining := remainingSeconds(now, effectiveResetAt)
		info := managementBanInfo{
			AuthID:                    authID,
			Window:                    entry.Window,
			ResetAt:                   entry.ResetAt.Format(time.RFC3339),
			ResetAtUnix:               entry.ResetAt.Unix(),
			RemainingSeconds:          remaining,
			CPAAuthFound:              cpaFound,
			EffectiveResetAt:          effectiveResetAt.Format(time.RFC3339),
			EffectiveResetAtUnix:      effectiveResetAt.Unix(),
			EffectiveRemainingSeconds: effectiveRemaining,
			EffectiveResetSource:      effectiveResetSource,
		}
		if cpaFound {
			info.CPAStatus = cpaAuth.Status
			info.CPAStatusMessage = cpaAuth.StatusMessage
			info.CPAUnavailable = cpaAuth.Unavailable
			if !cpaAuth.NextRetryAfter.IsZero() {
				info.CPANextRetryAfter = cpaAuth.NextRetryAfter.Format(time.RFC3339)
				info.CPANextRetryAfterUnix = cpaAuth.NextRetryAfter.Unix()
			}
		}
		if !entry.BannedAt.IsZero() {
			info.BannedAt = entry.BannedAt.Format(time.RFC3339)
			info.BannedAtUnix = entry.BannedAt.Unix()
		}
		bans = append(bans, info)
	}
	sort.Slice(bans, func(i, j int) bool {
		if bans[i].ResetAtUnix == bans[j].ResetAtUnix {
			return bans[i].AuthID < bans[j].AuthID
		}
		return bans[i].ResetAtUnix < bans[j].ResetAtUnix
	})
	status.Count = len(bans)
	status.Bans = bans
	return status
}

func remainingSeconds(now, target time.Time) int64 {
	if target.IsZero() || !now.Before(target) {
		return 0
	}
	return int64(target.Sub(now).Seconds())
}

type managementUnbanRequest struct {
	AuthID string `json:"auth_id"`
	All    bool   `json:"all"`
}

type managementResetBanRequest struct {
	AuthID string `json:"auth_id"`
}

func handleManagementUnban(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var body managementUnbanRequest
	if len(req.Body) > 0 {
		if errUnmarshal := json.Unmarshal(req.Body, &body); errUnmarshal != nil {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{
				"error":   "invalid_json",
				"message": errUnmarshal.Error(),
			})
		}
	}
	if strings.EqualFold(req.Query.Get("all"), "true") || body.All {
		return handleManagementUnbanAll()
	}

	authID := strings.TrimSpace(body.AuthID)
	if authID == "" {
		authID = strings.TrimSpace(req.Query.Get("auth_id"))
	}
	if authID == "" {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{
			"error":   "missing_auth_id",
			"message": "provide auth_id in JSON body or query string",
		})
	}

	entry, removed := banStore.clear(authID)
	if removed {
		slog.Info("codex-429-autoban: manually re-enabled credential",
			"auth_id", authID, "window", entry.Window, "reset_at", entry.ResetAt.Format(time.RFC3339))
	}
	return jsonManagementResponse(http.StatusOK, map[string]any{
		"ok":      true,
		"auth_id": authID,
		"removed": removed,
		"status":  currentBanStatus(),
	})
}

func handleManagementResetBan(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var body managementResetBanRequest
	if len(req.Body) > 0 {
		if errUnmarshal := json.Unmarshal(req.Body, &body); errUnmarshal != nil {
			return jsonManagementResponse(http.StatusBadRequest, map[string]any{
				"error":   "invalid_json",
				"message": errUnmarshal.Error(),
			})
		}
	}

	authID := strings.TrimSpace(body.AuthID)
	if authID == "" {
		authID = strings.TrimSpace(req.Query.Get("auth_id"))
	}
	if authID == "" {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{
			"error":   "missing_auth_id",
			"message": "provide auth_id in JSON body or query string",
		})
	}

	now := time.Now()
	if !banStore.clearIfExpired(authID, now) {
		if _, exists := banStore.lookup(authID); !exists {
			return jsonManagementResponse(http.StatusNotFound, map[string]any{
				"error":   "ban_not_found",
				"message": "auth is not currently in the plugin ban list",
				"auth_id": authID,
			})
		}
	}

	entry, exists := banStore.lookup(authID)
	if !exists {
		return jsonManagementResponse(http.StatusNotFound, map[string]any{
			"error":   "ban_not_found",
			"message": "auth is not currently in the plugin ban list",
			"auth_id": authID,
		})
	}

	// Use the same effective reset time shown by the status page: the later
	// of the plugin reset and CPA's next_retry_after, when CPA exposes one.
	effectiveResetAt := entry.ResetAt
	effectiveResetSource := "plugin"
	if entries, errHost := hostAuthEntries(); errHost == nil {
		if cpaAuth, cpaFound := findHostAuthEntry(entries, authID); cpaFound && !cpaAuth.NextRetryAfter.IsZero() && cpaAuth.NextRetryAfter.After(effectiveResetAt) {
			effectiveResetAt = cpaAuth.NextRetryAfter
			effectiveResetSource = "cpa"
		}
	}
	if effectiveResetAt.IsZero() || !now.Before(effectiveResetAt) {
		return jsonManagementResponse(http.StatusConflict, map[string]any{
			"error":   "reset_time_expired",
			"message": "the recorded reset time has already passed; wait for a new 429 or use a fresh ban record",
			"auth_id": authID,
		})
	}

	window := entry.Window
	if !strings.HasPrefix(window, "manual reset") {
		window = "manual reset (" + window + ")"
	}
	entry.ResetAt = effectiveResetAt
	entry.Window = window
	entry.BannedAt = now
	banStore.set(authID, entry)
	slog.Info("codex-429-autoban: manually reset credential ban",
		"auth_id", authID,
		"window", entry.Window,
		"reset_at", effectiveResetAt.Format(time.RFC3339),
		"reset_source", effectiveResetSource)

	return jsonManagementResponse(http.StatusOK, map[string]any{
		"ok":                     true,
		"auth_id":                authID,
		"reset_at":               effectiveResetAt.Format(time.RFC3339),
		"reset_at_unix":          effectiveResetAt.Unix(),
		"effective_reset_source": effectiveResetSource,
		"status":                 currentBanStatus(),
	})
}

func handleManagementUnbanAll() pluginapi.ManagementResponse {
	removed := banStore.clearAll()
	if removed > 0 {
		slog.Info("codex-429-autoban: manually re-enabled all credentials", "removed", removed)
	}
	return jsonManagementResponse(http.StatusOK, map[string]any{
		"ok":      true,
		"removed": removed,
		"status":  currentBanStatus(),
	})
}

func handleManagementTestWebhook() pluginapi.ManagementResponse {
	cfg := configuredPlugin()
	if cfg.DiscordWebhookURL == "" {
		return jsonManagementResponse(http.StatusBadRequest, map[string]any{
			"error":   "discord_webhook_not_configured",
			"message": "configure discord_webhook_url before testing the webhook",
		})
	}

	stats := currentCodexPoolStats("")
	poolText := "未知"
	if stats.Known {
		poolText = fmt.Sprintf("%d / %d", stats.Available, stats.Total)
	}
	payload := discordWebhookPayload{
		Username: discordWebhookTitle,
		Embeds: []discordEmbed{{
			Title:     "Discord Webhook 测试成功",
			Color:     5763719,
			Fields:    []discordField{{Name: "Codex 号池可用 / 总数", Value: poolText, Inline: true}},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Footer:    discordFooter{Text: pluginName + " v" + pluginVersion},
		}},
	}
	if errMention := addDiscordMention(&payload, cfg.DiscordMention); errMention != nil {
		return jsonManagementResponse(http.StatusInternalServerError, map[string]any{
			"error":   "invalid_discord_mention",
			"message": errMention.Error(),
		})
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return jsonManagementResponse(http.StatusInternalServerError, map[string]any{
			"error":   "encode_webhook_payload_failed",
			"message": errMarshal.Error(),
		})
	}
	if errPost := postDiscordWebhook(cfg.DiscordWebhookURL, raw); errPost != nil {
		return jsonManagementResponse(http.StatusBadGateway, map[string]any{
			"error":   "discord_webhook_failed",
			"message": errPost.Error(),
		})
	}
	return jsonManagementResponse(http.StatusOK, map[string]any{
		"ok":             true,
		"message":        "Discord webhook test sent",
		"pool_available": stats.Available,
		"pool_total":     stats.Total,
		"pool_known":     stats.Known,
	})
}

func matchesManagementPath(path, suffix string) bool {
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if path == "" {
		return false
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return strings.HasSuffix(path, managementRoutePrefix+suffix)
}

func matchesResourcePath(path, suffix string) bool {
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if path == "" {
		return false
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return strings.HasSuffix(path, "/v0/resource/plugins/"+pluginName+suffix) ||
		strings.HasSuffix(path, "/plugins/"+pluginName+suffix)
}

func jsonManagementResponse(status int, v any) pluginapi.ManagementResponse {
	raw, errMarshal := json.MarshalIndent(v, "", "  ")
	if errMarshal != nil {
		status = http.StatusInternalServerError
		raw, _ = json.Marshal(map[string]any{
			"error":   "marshal_error",
			"message": errMarshal.Error(),
		})
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type": []string{"application/json; charset=utf-8"},
		},
		Body: raw,
	}
}

func htmlManagementResponse(status int, body string) pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		Body: []byte(body),
	}
}

func managementStatusPage() string {
	version := html.EscapeString(pluginVersion)
	return `<!doctype html>
<html lang="zh-Hans">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>codex-429-autoban</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { max-width: 980px; margin: 32px auto; padding: 0 16px; line-height: 1.5; }
    h1 { margin-bottom: 4px; }
    .muted { color: #667085; }
    .card { border: 1px solid #d0d7de; border-radius: 12px; padding: 16px; margin: 16px 0; }
    label { display: block; font-weight: 600; margin-bottom: 6px; }
    input { width: min(640px, 100%); padding: 8px 10px; border: 1px solid #d0d7de; border-radius: 8px; }
    button { cursor: pointer; padding: 8px 12px; border: 1px solid #d0d7de; border-radius: 8px; margin: 4px 4px 4px 0; }
    button.primary { background: #0969da; border-color: #0969da; color: white; }
    button.danger { background: #cf222e; border-color: #cf222e; color: white; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border-bottom: 1px solid #d0d7de; padding: 8px; text-align: left; vertical-align: top; }
    code { background: rgba(127,127,127,.15); padding: 2px 4px; border-radius: 4px; }
    pre { overflow: auto; background: rgba(127,127,127,.12); padding: 12px; border-radius: 8px; }
  </style>
</head>
<body>
  <h1>codex-429-autoban</h1>
  <p class="muted">版本 ` + version + ` · 按真实 reset time 管理 Codex 账号的 ban。</p>

  <div class="card">
    <p>资源页本身不带管理鉴权。要执行查看、重设 ban 或解除操作，请填入 CPA 管理密钥；请求会使用 <code>Authorization: Bearer &lt;key&gt;</code>。</p>
    <label for="key">CPA 管理密钥</label>
    <input id="key" type="password" autocomplete="current-password" placeholder="Management key">
    <div>
      <button class="primary" onclick="refresh()">刷新当前 ban 列表</button>
      <button onclick="testWebhook()">测试 Discord Webhook</button>
      <button class="danger" onclick="unbanAll()">全部加回号池</button>
    </div>
    <p id="message" class="muted"></p>
  </div>

  <div class="card">
    <h2>当前被插件排除的账号</h2>
    <p class="muted">“重新设置 ban”会按当前页面的“预计实际回池时间”重新写入插件内存，不会修改 Codex 侧额度。</p>
    <div id="list">尚未加载。</div>
  </div>

  <div class="card">
    <h2>API</h2>
    <pre>GET  /v0/management/plugins/codex-429-autoban/bans
POST /v0/management/plugins/codex-429-autoban/unban      {"auth_id":"..."}
POST /v0/management/plugins/codex-429-autoban/reset-ban  {"auth_id":"..."}
POST /v0/management/plugins/codex-429-autoban/unban-all
POST /v0/management/plugins/codex-429-autoban/test-webhook</pre>
  </div>

  <script>
    const apiBase = "/v0/management/plugins/codex-429-autoban";
    const keyInput = document.getElementById("key");
    const savedKey = localStorage.getItem("codex429AutobanManagementKey") || "";
    keyInput.value = savedKey;
    keyInput.addEventListener("change", function () {
      localStorage.setItem("codex429AutobanManagementKey", keyInput.value);
    });

    function headers() {
      const h = {"Content-Type": "application/json"};
      if (keyInput.value) h.Authorization = "Bearer " + keyInput.value;
      return h;
    }

    function setMessage(text, isError) {
      const el = document.getElementById("message");
      el.textContent = text || "";
      el.style.color = isError ? "#cf222e" : "";
    }

    async function call(path, options) {
      const resp = await fetch(apiBase + path, Object.assign({headers: headers()}, options || {}));
      const text = await resp.text();
      let data;
      try { data = JSON.parse(text); } catch (_) { data = {raw: text}; }
      if (!resp.ok) {
        throw new Error((data && (data.message || data.error)) || ("HTTP " + resp.status));
      }
      return data;
    }

    function formatRemaining(seconds) {
      seconds = Math.max(0, Number(seconds || 0));
      const h = Math.floor(seconds / 3600);
      const m = Math.floor((seconds % 3600) / 60);
      if (h > 0) return h + "h " + m + "m";
      return m + "m";
    }

    function formatCpaRetryAt(ban) {
      if (!ban.cpa_auth_found) {
        return "未找到 CPA 账号";
      }
      if (ban.cpa_next_retry_after) {
        return escapeHtml(ban.cpa_next_retry_after);
      }
      if (ban.cpa_unavailable) {
        return "CPA 当前无明确回池时间";
      }
      return "CPA 当前未设置冷却时间";
    }

    function formatEffectiveResetAt(ban) {
      if (ban.effective_reset_source === "unknown") {
        return "未知（CPA 未提供时间）";
      }
      const source = ban.effective_reset_source === "cpa" ? "CPA" :
        (ban.effective_reset_source === "plugin_and_cpa" ? "插件/CPA" : "插件");
      return escapeHtml(ban.effective_reset_at) + "（" + source + "）";
    }

    function formatEffectiveRemaining(ban) {
      if (ban.effective_reset_source === "unknown") {
        return "未知";
      }
      return formatRemaining(ban.effective_remaining_seconds);
    }

    function render(data) {
      const list = document.getElementById("list");
      if (!data.bans || data.bans.length === 0) {
        list.innerHTML = "<p>没有账号被插件 ban，号池无需手动恢复。</p>";
        return;
      }
      let html = "";
      if (!data.cpa_auth_list_available) {
        html += "<p class=\"muted\">CPA auth 列表读取失败，以下仅显示插件记录的时间。</p>";
      }
      html += "<table><thead><tr><th>Auth ID</th><th>窗口</th><th>插件解除时间</th><th>CPA 下次重试时间</th><th>预计实际回池时间</th><th>剩余</th><th>操作</th></tr></thead><tbody>";
      for (const ban of data.bans) {
        const cpaStatus = ban.cpa_status_message || ban.cpa_status || "";
        const cpaStatusTitle = cpaStatus ? " title=\"" + escapeHtml(cpaStatus) + "\"" : "";
       html += "<tr><td><code>" + escapeHtml(ban.auth_id) + "</code></td><td>" + escapeHtml(ban.window) + "</td><td>" + escapeHtml(ban.reset_at) + "</td><td" + cpaStatusTitle + ">" + formatCpaRetryAt(ban) + "</td><td>" + formatEffectiveResetAt(ban) + "</td><td>" + formatEffectiveRemaining(ban) + "</td><td><button onclick=\"resetBan('" + escapeJs(ban.auth_id) + "','" + escapeJs(ban.effective_reset_at) + "')\">重新设置 ban</button><button onclick=\"unban('" + escapeJs(ban.auth_id) + "')\">加回号池</button></td></tr>";
      }
      html += "</tbody></table>";
      list.innerHTML = html;
    }

    function escapeHtml(value) {
      return String(value || "").replace(/[&<>"']/g, function (c) {
        return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];
      });
    }

    function escapeJs(value) {
      return String(value || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
    }

    async function refresh() {
      try {
        setMessage("加载中...");
        const data = await call("/bans");
        render(data);
        setMessage("已刷新，共 " + data.count + " 个账号被排除。");
      } catch (err) {
        setMessage(err.message, true);
      }
    }

    async function testWebhook() {
      try {
        setMessage("正在发送 Discord 测试消息...");
        const data = await call("/test-webhook", {method: "POST", body: "{}"});
        const pool = data.pool_known ? (data.pool_available + " / " + data.pool_total) : "未知";
        setMessage("Discord 测试消息已发送；当前 Codex 号池可用/总数：" + pool + "。", false);
      } catch (err) {
        setMessage(err.message, true);
      }
    }

    async function resetBan(authID, effectiveResetAt) {
      if (!confirm("确认按照预计实际回池时间重新设置 " + authID + " 的 ban？\n解禁时间：" + effectiveResetAt)) return;
      try {
        const data = await call("/reset-ban", {method: "POST", body: JSON.stringify({auth_id: authID})});
        render(data.status);
        setMessage("已重新设置 ban：" + authID + "；解禁时间：" + data.reset_at);
      } catch (err) {
        setMessage(err.message, true);
      }
    }

    async function unban(authID) {
      if (!confirm("确认将 " + authID + " 加回号池？")) return;
      try {
        const data = await call("/unban", {method: "POST", body: JSON.stringify({auth_id: authID})});
        render(data.status);
        setMessage(data.removed ? "已加回号池：" + authID : "该账号当前不在 ban 列表：" + authID);
      } catch (err) {
        setMessage(err.message, true);
      }
    }

    async function unbanAll() {
      if (!confirm("确认清空全部 ban 状态？")) return;
      try {
        const data = await call("/unban-all", {method: "POST", body: "{}"});
        render(data.status);
        setMessage("已解除 " + data.removed + " 个账号。");
      } catch (err) {
        setMessage(err.message, true);
      }
    }
  </script>
</body>
</html>`
}

// ---- header helpers ----

func headerFloat(h http.Header, key string) float64 {
	raw := h.Get(key)
	if raw == "" {
		return 0
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0
	}
	return v
}

func headerInt(h http.Header, key string) int {
	raw := h.Get(key)
	if raw == "" {
		return 0
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return v
}

func headerUnixTime(h http.Header, key string) time.Time {
	raw := h.Get(key)
	if raw == "" {
		return time.Time{}
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}
	}
	if secs <= 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0)
}

// ---- envelope / response helpers ----

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	UsagePlugin   bool `json:"usage_plugin"`
	Scheduler     bool `json:"scheduler"`
	ManagementAPI bool `json:"management_api"`
}

func okEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
