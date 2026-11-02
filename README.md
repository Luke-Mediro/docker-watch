# docker-watch
Golang code I wrote, useful but boring in a docker only server environment. 

Description: 
docker-watch: a tiny Docker event watcher & alerter.

It streams the Docker events API and alerts on:
 - restart loops      (a container dying repeatedly in a short window)
 - OOM kills          (container killed by the kernel OOM killer)
 - unexpected exits   (non-zero exit codes that aren't clean stops)
 - health flips       (healthcheck goes unhealthy)

Alerts are POSTed as JSON to a webhook URL, or formatted for Slack
if ALERT_FORMAT=slack. Point WEBHOOK_URL at anything that accepts JSON.

Why this tool exists: restart policies (restart: always / unless-stopped)
hide crash loops. A container can silently restart every 10 seconds for
a week and nothing will tell you. This watcher makes those loops loud.

The design is deliberately boring: one main loop, in-memory state, no
persistence, no plugins. If it crashes it just starts counting from zero.
Low entry, low hazard.
