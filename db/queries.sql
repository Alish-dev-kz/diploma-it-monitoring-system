-- ITMon: жүйенің негізгі сұраулары (SQLite 3.35+)
-- "Now" is fixed to the moment of the test data so results are reproducible.
-- In production replace '2026-11-20 10:00:00' with datetime('now').

.headers on
.mode column

-- Q1. Dashboard: devices with group, online/offline state and the latest value of every metric
--     (UC-03 "Құрылғылар тізімін көру", screen 3)
WITH latest AS (
    SELECT m.device_id, mt.code, m.value,
           ROW_NUMBER() OVER (PARTITION BY m.device_id, m.metric_type_id ORDER BY m.measured_at DESC) AS rn
    FROM metrics m JOIN metric_types mt ON mt.id = m.metric_type_id
)
SELECT d.hostname,
       g.name AS device_group,
       CASE WHEN d.last_seen IS NULL THEN 'never'
            WHEN (julianday('2026-11-20 10:00:00') - julianday(d.last_seen)) * 86400 > 30 THEN 'offline'
            ELSE 'online' END AS state,
       MAX(CASE WHEN l.code = 'cpu'  THEN l.value END) AS cpu,
       MAX(CASE WHEN l.code = 'ram'  THEN l.value END) AS ram,
       MAX(CASE WHEN l.code = 'disk' THEN l.value END) AS disk
FROM devices d
LEFT JOIN device_groups g ON g.id = d.group_id
LEFT JOIN latest l ON l.device_id = d.id AND l.rn = 1
GROUP BY d.id
ORDER BY state DESC, d.hostname;

-- Q2. "Difficult part": threshold exceeded in N latest samples in a row (N = consecutive_count).
--     A single spike (LAB301-PC01, CPU 99%) must not be returned. (UC-08, sequence diagram 1)
WITH ranked AS (
    SELECT m.device_id, m.metric_type_id, m.value,
           ROW_NUMBER() OVER (PARTITION BY m.device_id, m.metric_type_id ORDER BY m.measured_at DESC) AS rn
    FROM metrics m
),
rule AS (  -- group-specific threshold overrides the global one
    SELECT d.id AS device_id, t.metric_type_id, t.warn_value, t.crit_value, t.consecutive_count
    FROM devices d
    JOIN thresholds t ON t.group_id = d.group_id
       OR (t.group_id IS NULL AND NOT EXISTS (
              SELECT 1 FROM thresholds t2 WHERE t2.metric_type_id = t.metric_type_id AND t2.group_id = d.group_id))
)
SELECT d.hostname, mt.code AS metric,
       r.consecutive_count AS n,
       MIN(k.value) AS min_in_window,
       CASE WHEN MIN(k.value) >= r.crit_value THEN 'crit' ELSE 'warn' END AS level
FROM ranked k
JOIN rule r ON r.device_id = k.device_id AND r.metric_type_id = k.metric_type_id
JOIN devices d ON d.id = k.device_id
JOIN metric_types mt ON mt.id = k.metric_type_id
WHERE k.rn <= r.consecutive_count
GROUP BY k.device_id, k.metric_type_id
HAVING COUNT(*) = r.consecutive_count AND MIN(k.value) >= r.warn_value;

-- Q3. "Difficult part": command queue maintenance.
--     3a) pending commands whose TTL has passed become 'expired' (agent was offline too long)
UPDATE commands SET status = 'expired', finished_at = '2026-11-20 10:00:00'
WHERE status = 'pending' AND expires_at < '2026-11-20 10:00:00';
--     3b) commands the agent BUH-PC03 receives on its next poll
SELECT c.id, ct.code AS command, c.attempts, c.expires_at
FROM commands c
JOIN command_types ct ON ct.id = c.command_type_id
JOIN devices d ON d.id = c.device_id
WHERE d.hostname = 'BUH-PC03' AND c.status = 'pending'
ORDER BY c.id;

-- Q4. Open alerts by group: how many and how long the oldest one waits (UC-07, screen 5)
SELECT g.name AS device_group,
       COUNT(*) AS open_alerts,
       SUM(a.level = 'crit') AS critical,
       MIN(a.created_at) AS oldest,
       ROUND((julianday('2026-11-20 10:00:00') - julianday(MIN(a.created_at))) * 24, 1) AS hours_waiting
FROM alerts a
JOIN devices d ON d.id = a.device_id
JOIN device_groups g ON g.id = d.group_id
WHERE a.status IN ('open', 'acknowledged')
GROUP BY g.id
ORDER BY critical DESC, open_alerts DESC;

-- Q5. Engineer workload: active incidents per engineer (UC-11)
SELECT u.full_name,
       SUM(i.status = 'new')         AS new_incidents,
       SUM(i.status = 'in_progress') AS in_progress,
       SUM(i.status = 'closed')      AS closed
FROM users u
JOIN roles r ON r.id = u.role_id AND r.code = 'engineer'
LEFT JOIN incidents i ON i.assigned_to = u.id
GROUP BY u.id
ORDER BY in_progress + new_incidents DESC;

-- Q6. Remote command statistics per command type: success rate and expired share (UC-09, report)
SELECT ct.code AS command,
       COUNT(c.id) AS total,
       SUM(c.status = 'done')    AS done,
       SUM(c.status = 'expired') AS expired,
       SUM(c.status = 'failed')  AS failed,
       ROUND(100.0 * SUM(c.status = 'done') / NULLIF(COUNT(c.id), 0), 1) AS success_pct
FROM command_types ct
LEFT JOIN commands c ON c.command_type_id = ct.id
GROUP BY ct.id
ORDER BY total DESC;

-- Q7. Audit: who sent remote commands and to which device (UC-14, change card #10)
SELECT a.created_at, u.full_name, r.name AS role, a.details
FROM audit_log a
JOIN users u ON u.id = a.user_id
JOIN roles r ON r.id = u.role_id
WHERE a.action = 'queue_command'
ORDER BY a.created_at DESC;
