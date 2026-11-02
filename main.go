package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// config holds everything the watcher reads from the environment.
// Reading it once up front makes misconfiguration fail fast, before we
// touch the Docker socket. All knobs have sensible defaults except
//  WEBHOOK_URL, which has no sensible default.
type config struct {
	webhookURL       string
	alertFormat      string        // "json" (default) or "slack"
	restartWindow    time.Duration // lookback window for restart-loop detection
	restartThreshold int           // number of dies in restart Window to trigger
	alertCooldown    time.Duration // minimum time between identical alerts
	excludeNames     map[string]struct{}
}

func loadConfig() (config, error) {
	c := config{
		webhookURL:       os.Getenv("WEBHOOK_URL"),
		alertFormat:      strings.ToLower(os.Getenv("ALERT_FORMAT")),
		restartWindow:    5 * time.Minute,
		restartThreshold: 3,
		alertCooldown:    10 * time.Minute,
		excludeNames:     map[string]struct{}{},
	}

	if c.webhookURL == "" {
		return c, fmt.Errorf("WEBHOOK_URL is required")
	}
	if c.alertFormat == "" {
		c.alertFormat = "json"
	}
	if c.alertFormat != "json" && c.alertFormat != "slack" {
		return c, fmt.Errorf("ALERT_FORMAT must be 'json' or 'slack', got %q", c.alertFormat)
	}

	if v := os.Getenv("RESTART_WINDOW"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("RESTART_WINDOW: %w", err)
		}
		c.restartWindow = d
	}
	if v := os.Getenv("RESTART_THRESHOLD"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 {
			return c, fmt.Errorf("RESTART_THRESHOLD must be a positive integer, got %q", v)
		}
		c.restartThreshold = n
	}
	if v := os.Getenv("ALERT_COOLDOWN"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("ALERT_COOLDOWN: %w", err)
		}
		c.alertCooldown = d
	}

	for _, n := range strings.Split(os.Getenv("EXCLUDE_NAMES"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			c.excludeNames[n] = struct{}{}
		}
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Alert payload
// ---------------------------------------------------------------------------

// alert is the JSON payload we POST to the webhook.
// Keep this stable and boring: downstream systems will parse it.
type alert struct {
	Type        string    `json:"type"`
	Container   string    `json:"container"`
	ContainerID string    `json:"container_id"`
	Host        string    `json:"host"`
	Message     string    `json:"message"`
	ExitCode    string    `json:"exit_code,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Watcher
// ---------------------------------------------------------------------------

// watcher is the stateful core. We keep per-container history in memory
// so we can spot patterns (restart loops) and avoid spamming the webhook
// (per-alert cooldowns). State is intentionally non-persistent.
type watcher struct {
	cli  *client.Client
	cfg  config
	host string

	mu        sync.Mutex
	dies      map[string][]time.Time // containerID -> recent die timestamps
	lastAlert map[string]time.Time   // "containerID:alertType" -> last alert time
}

// stream subscribes to Docker events and dispatches each message.
// It returns when the stream errors or the context is cancelled.
func (w *watcher) stream(ctx context.Context) error {
	msgs, errs := w.cli.Events(ctx, events.ListOptions{})
	log.Printf("streaming docker events on %s", w.host)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-errs:
			if !ok {
				return fmt.Errorf("error channel closed")
			}
			if err != nil {
				return err
			}
		case ev, ok := <-msgs:
			if !ok {
				return fmt.Errorf("event channel closed")
			}
			w.handle(ctx, ev)
		}
	}
}

// handle is the single decision point: filter, then route by action.
func (w *watcher) handle(ctx context.Context, ev events.Message) {
	name := ev.Actor.Attributes["name"]
	if _, skip := w.cfg.excludeNames[name]; skip {
		return
	}

	action := string(ev.Action)
	switch {
	case action == "die":
		w.handleDie(ctx, ev, name)
	case action == "oom":
		w.alert(ctx, alert{
			Type:        "oom_kill",
			Container:   name,
			ContainerID: ev.Actor.ID,
			Host:        w.host,
			Message:     fmt.Sprintf("container %s was killed by the OOM killer", name),
			Timestamp:   eventTime(ev),
		})
	case strings.HasPrefix(action, "health_status"):
		w.handleHealth(ctx, ev, name)
	}
}

// handleDie covers both unexpected exits and restart-loop detection.
// A single die event can legitimately produce both an exit alert and a
// restart-loop alert; the per-type cooldown keeps that from being spammy.
func (w *watcher) handleDie(ctx context.Context, ev events.Message, name string) {
	exitCode := ev.Actor.Attributes["exitCode"]
	oomKilled := ev.Actor.Attributes["oomKilled"] == "true"
	id := ev.Actor.ID

	// Track this die for restart-loop detection.
	// We prune old entries in the same lock so the map doesn't grow forever.
	w.mu.Lock()
	now := time.Now()
	cutoff := now.Add(-w.cfg.restartWindow)
	recent := w.dies[id][:0] // reuse backing array
	for _, t := range w.dies[id] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	w.dies[id] = recent
	count := len(recent)
	w.mu.Unlock()

	// OOM: trust the oomKilled attribute over the exit code. 137 is
	// SIGKILL and covers both OOM and manual `kill -9`; only flag it as
	// OOM if Docker says so. Otherwise 137 falls through to the
	// unexpected-exit path, which is what you want.
	if oomKilled {
		w.alert(ctx, alert{
			Type:        "oom_kill",
			Container:   name,
			ContainerID: id,
			Host:        w.host,
			ExitCode:    exitCode,
			Message:     fmt.Sprintf("container %s was OOM-killed (exit %s)", name, exitCode),
			Timestamp:   eventTime(ev),
		})
	} else if isUnexpectedExit(exitCode) {
		w.alert(ctx, alert{
			Type:        "unexpected_exit",
			Container:   name,
			ContainerID: id,
			Host:        w.host,
			ExitCode:    exitCode,
			Message:     fmt.Sprintf("container %s exited unexpectedly with code %s", name, exitCode),
			Timestamp:   eventTime(ev),
		})
	}

	// Restart loop: too many dies in the window.
	if count >= w.cfg.restartThreshold {
		w.alert(ctx, alert{
			Type:        "restart_loop",
			Container:   name,
			ContainerID: id,
			Host:        w.host,
			Message:     fmt.Sprintf("container %s died %d times in %s", name, count, w.cfg.restartWindow),
			Timestamp:   eventTime(ev),
		})
	}
}

// handleHealth alerts only on transitions to "unhealthy".
// We deliberately don't alert on "healthy" — nobody wants a ping
// every time a flaky healthcheck recovers.
func (w *watcher) handleHealth(ctx context.Context, ev events.Message, name string) {
	// The attribute is the canonical source; fall back to parsing the
	// action string ("health_status: unhealthy") if it's missing.
	status := ev.Actor.Attributes["health_status"]
	if status == "" {
		if i := strings.Index(string(ev.Action), ": "); i >= 0 {
			status = string(ev.Action)[i+2:]
		}
	}
	if status != "unhealthy" {
		return
	}
	w.alert(ctx, alert{
		Type:        "health_unhealthy",
		Container:   name,
		ContainerID: ev.Actor.ID,
		Host:        w.host,
		Message:     fmt.Sprintf("container %s healthcheck is failing", name),
		Timestamp:   eventTime(ev),
	})
}

// alert applies a per-(container,type) cooldown and, if it passes, posts
// the alert. The cooldown is the whole reason this tool is usable: a
// container in a tight crash loop dies every few seconds, and without
// cooldown we'd be hammering the webhook.
func (w *watcher) alert(ctx context.Context, a alert) {
	key := a.ContainerID + ":" + a.Type
	w.mu.Lock()
	if last, ok := w.lastAlert[key]; ok && time.Since(last) < w.cfg.alertCooldown {
		w.mu.Unlock()
		return
	}
	w.lastAlert[key] = time.Now()
	w.mu.Unlock()

	log.Printf("[%s] %s: %s", a.Type, a.Container, a.Message)
	if err := w.post(ctx, a); err != nil {
		log.Printf("post webhook: %v", err)
	}
}

// post serialises the alert and sends it.
func (w *watcher) post(ctx context.Context, a alert) error {
	var body []byte
	var err error
	switch w.cfg.alertFormat {
	case "slack":
		// Slack incoming webhooks accept a "text" field.
		// See https://api.slack.com/messaging/webhooks
		body, err = json.Marshal(map[string]string{
			"text": fmt.Sprintf(":rotating_light: *%s* on `%s`\n%s", a.Type, a.Container, a.Message),
		})
	default:
		body, err = json.Marshal(a)
	}
	if err != nil {
		return err
	}

	// Always give the HTTP call a deadline. Without this a hung webhook
	// would silently block the whole event loop.
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, w.cfg.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// run keeps the event stream alive. Docker's events endpoint will
// periodically drop or error out (daemon restart, network blip); a real
// SRE tool reconnects with exponential backoff instead of exiting.
func (w *watcher) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := w.stream(ctx)
		if ctx.Err() != nil {
			return
		}
		log.Printf("event stream ended: %v (reconnecting in %s)", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isUnexpectedExit decides whether an exit code warrants an alert.
// We filter out codes that typically mean "this was a clean, intentional
// stop":
//   0   – success
//   130 – SIGINT  (Ctrl-C / `docker stop` in some cases)
//   143 – SIGTERM (`docker stop`, `docker compose down`)
// Everything else is flagged. 137 (SIGKILL) is included because without
// the oomKilled attribute it usually means something hard-killed the
// container, which is worth knowing about.
func isUnexpectedExit(code string) bool {
	switch code {
	case "", "0", "130", "143":
		return false
	}
	return true
}

// eventTime returns the event time as time.Time. The SDK gives us
// nanoseconds since epoch; fall back to time.Now if it's zero.
func eventTime(ev events.Message) time.Time {
	if ev.TimeNano > 0 {
		return time.Unix(0, ev.TimeNano)
	}
	if ev.Time > 0 {
		return time.Unix(ev.Time, 0)
	}
	return time.Now()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}

	// client.FromEnv picks up DOCKER_HOST etc.
	// WithAPIVersionNegotiation() lets us talk to whatever daemon
	// version is on the other end of the socket, which is exactly what
	// you want in a dev environment where laptops, CI, and staging all
	// run slightly different Docker versions.
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("docker client: %v", err)
	}
	defer cli.Close()

	// Cancel on SIGINT/SIGTERM so we exit cleanly under `docker stop`.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	w := &watcher{
		cli:       cli,
		cfg:       cfg,
		host:      host,
		dies:      make(map[string][]time.Time),
		lastAlert: make(map[string]time.Time),
	}
	w.run(ctx)
	log.Println("shutting down")
}
