-- +goose Up
CREATE INDEX audit_page ON audit_logs(created_at DESC,id DESC);

-- +goose Down
DROP INDEX audit_page;
