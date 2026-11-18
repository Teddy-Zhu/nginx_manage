-- +goose Up
CREATE TABLE realtime_task_revision (
    id INTEGER PRIMARY KEY CHECK(id=1),
    revision INTEGER NOT NULL
);
INSERT INTO realtime_task_revision(id,revision) VALUES(1,0);

-- +goose StatementBegin
CREATE TRIGGER realtime_task_insert AFTER INSERT ON tasks BEGIN
    UPDATE realtime_task_revision SET revision=revision+1 WHERE id=1;
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER realtime_task_update AFTER UPDATE ON tasks BEGIN
    UPDATE realtime_task_revision SET revision=revision+1 WHERE id=1;
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER realtime_task_delete AFTER DELETE ON tasks BEGIN
    UPDATE realtime_task_revision SET revision=revision+1 WHERE id=1;
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER realtime_task_delete;
DROP TRIGGER realtime_task_update;
DROP TRIGGER realtime_task_insert;
DROP TABLE realtime_task_revision;
