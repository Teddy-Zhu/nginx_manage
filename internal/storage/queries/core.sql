-- name: GetSetting :one
SELECT value FROM settings WHERE key = ?;

-- name: PutSetting :exec
INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;

-- name: GetUser :one
SELECT * FROM users WHERE id=1;

-- name: GetConfigHead :one
SELECT * FROM config_head WHERE id=1;

-- name: GetRevision :one
SELECT * FROM config_revisions WHERE id=?;

-- name: GetRevisionFiles :many
SELECT * FROM nginx_config_files WHERE revision_id=? ORDER BY path;

-- name: GetRevisionBindings :many
SELECT * FROM nginx_resource_bindings WHERE revision_id=? ORDER BY resource_id;

-- name: ListRevisions :many
SELECT id,parent_id,version,state,created_at,created_by FROM config_revisions ORDER BY version DESC LIMIT ? OFFSET ?;

-- name: GetTask :one
SELECT * FROM tasks WHERE id=?;

-- name: ListTasks :many
SELECT * FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?;
