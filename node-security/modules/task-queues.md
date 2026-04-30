---
name: Task Queue Security Patterns
description: Serializer choice, arg validation, privilege boundaries, broker auth, schedules, BullMQ/Agenda
applies_to:
  - feature: task-queue
  - dependency: bullmq
  - dependency: bull
  - dependency: agenda
  - dependency: bee-queue
  - dependency: kue
version: 1
last_updated: 2026-04-30
---

# Task Queue Security Patterns

Apply when the project uses BullMQ, Bull, Agenda, Bee-Queue, or other Node task queues.

## 1. Argument Serialization & Trust

**Red Flags:**
```js
// VULNERABLE - job data includes a function name to dispatch
queue.add("dispatch", { handler: req.body.handler, args: req.body.args });
worker.process(async (job) => handlers[job.data.handler](...job.data.args));
// attacker enqueues arbitrary handler

// VULNERABLE - unbounded payload
queue.add("export", { html: req.body.html });                   // 10MB payload, executed later
```

**Checklist:**
- [ ] Job payloads contain only data, never function names / module paths to dynamically resolve
- [ ] Worker dispatches by static job type (`worker.on("ready", () => worker.process("export", exportJob))`); attacker
      cannot redirect dispatch
- [ ] Payload size bounded; Redis-backed queues have practical limits but enforce explicitly
- [ ] Payload schema validated when the worker pulls it - do not trust your own enqueuer if it accepted user input

## 2. Authentication Context

**Red Flags:**
```js
// VULNERABLE - worker assumes admin privileges; uses no scope
worker.process(async (job) => {
  await db.user.delete({ where: { id: job.data.userId } });     // any caller's job deletes any user
});

// VULNERABLE - userId pulled from a global, not the job
let currentUser;
worker.process(async (job) => {
  await processWithUser(currentUser);                            // currentUser is whatever leaked into the worker
});
```

**Checklist:**
- [ ] Job payload carries `tenantId` / `userId` explicitly; worker uses these for scoping
- [ ] Worker re-validates that the operation is permitted (the user existed, still has the role, still owns the
      resource) - the job may be old
- [ ] Workers run with a service account scoped to job-required permissions; not "admin for everything"

## 3. Broker Authentication

**Checklist:**
- [ ] Redis (BullMQ/Bull/Bee) uses ACL with per-app credentials; not the default `nopass` user
- [ ] TLS enabled on broker connection (`rediss://` URL); `rejectUnauthorized: true`
- [ ] Broker not exposed to public internet; security group / firewall scoped to the cluster
- [ ] Broker eviction policy (`maxmemory-policy`) reviewed - `noeviction` for queues prevents silent job loss

## 4. Repeatable / Scheduled Jobs

**Red Flags:**
```js
// VULNERABLE - cron expression from user input
queue.add("report", { ... }, { repeat: { pattern: req.body.cron } });
// 0 0 1 1 *  is OK; * * * * *  fires every minute - amplification attack
```

**Checklist:**
- [ ] Cron expressions / repeat patterns validated against an allowlist or minimum-interval constraint
- [ ] Repeated job IDs deduplicated (BullMQ `repeat.jobId`) to prevent attacker creating thousands of identical
      schedules
- [ ] Per-tenant quotas on number of active scheduled jobs

## 5. Failure Handling / DLQ

**Checklist:**
- [ ] Job retries bounded (`attempts: N`); backoff configured (`backoff: { type: 'exponential' }`)
- [ ] Dead-letter queue (failed jobs) reviewed regularly; not silently growing
- [ ] Sensitive data in failed-job payloads (tokens, PII) redacted before persisting in DLQ
- [ ] `removeOnComplete` / `removeOnFail` set to bounded counts; otherwise Redis fills with completed-job records

## 6. Worker Concurrency / Resource Limits

**Checklist:**
- [ ] Concurrency per worker bounded; no `concurrency: Infinity`
- [ ] Per-job timeout (`job.opts.timeout` or worker-side `AbortSignal`) - prevents stuck jobs holding resources
- [ ] Memory-heavy jobs run on separate worker processes / queues to limit blast radius

## 7. UI / Admin Dashboard

**Red Flags:**
```js
// VULNERABLE - bull-board or arena exposed without auth
app.use("/admin/queues", arenaRouter);
```

**Checklist:**
- [ ] BullMQ Dashboard / Bull Board / Arena auth-gated (basic auth + IP allowlist at minimum, role-based ideally)
- [ ] Read-only access for ops; only specific roles can retry / remove jobs
- [ ] Dashboard not exposed publicly even temporarily

## 8. Webhooks Triggered by Jobs

**Checklist:**
- [ ] Outbound webhooks from jobs go through SSRF guard - same rules as request-time webhook calls (see SKILL.md SSRF)
- [ ] Webhook destination URLs validated when stored; re-validated at send time (TOCTOU defense)
- [ ] Per-tenant webhook send rate limit; per-destination concurrency cap

## 9. Cross-Tenant Job Isolation

**Checklist:**
- [ ] Job names / queue names per-tenant when feasible, OR `tenantId` in payload is enforced before any DB access
- [ ] One tenant's job failures do not stall another tenant's queue (separate workers / priority queues)

## References

- BullMQ: https://docs.bullmq.io/
- Redis ACL: https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/
