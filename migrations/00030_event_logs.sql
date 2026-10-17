-- +goose Up
INSERT INTO settings(key,value) VALUES('event_log_epoch',lower(hex(randomblob(16))));
CREATE TABLE event_log_queue (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL CHECK(length(payload)<=2048)
);
CREATE TABLE event_log_status (id INTEGER PRIMARY KEY CHECK(id=1),dropped INTEGER NOT NULL DEFAULT 0,paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN(0,1)));
INSERT INTO event_log_status(id) VALUES(1);

-- Stage events are committed with their task, including intermediate stages.
-- Error text and resource names are intentionally excluded.
-- +goose StatementBegin
CREATE TRIGGER task_log_insert AFTER INSERT ON tasks WHEN (SELECT paused FROM event_log_status WHERE id=1)=0 BEGIN
    INSERT INTO event_log_queue(payload) SELECT json_object(
        'time',max(NEW.created_at,1),'category','task','level','info','code','task.created',
        'task_id',NEW.id,'kind',CASE WHEN length(NEW.kind)<=192 AND NEW.kind NOT GLOB '*[^a-zA-Z0-9._/-]*' THEN NEW.kind ELSE 'unavailable' END,
        'state',NEW.state,'stage',CASE WHEN length(NEW.stage)<=96 AND NEW.stage NOT GLOB '*[^a-zA-Z0-9._/-]*' THEN NEW.stage ELSE 'unavailable' END,
        'request_id','','count',0) WHERE (SELECT COUNT(*) FROM event_log_queue)<8192;
    UPDATE event_log_status SET dropped=min(dropped+1,9223372036854775807) WHERE changes()=0;
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER task_log_update AFTER UPDATE OF state,stage ON tasks WHEN (NEW.state<>OLD.state OR NEW.stage<>OLD.stage) AND (SELECT paused FROM event_log_status WHERE id=1)=0 BEGIN
    INSERT INTO event_log_queue(payload) SELECT json_object(
        'time',max(NEW.updated_at,1),'category','task','level',CASE WHEN NEW.state IN('failed','recovery_required') THEN 'error' ELSE 'info' END,'code','task.transition',
        'task_id',NEW.id,'kind',CASE WHEN length(NEW.kind)<=192 AND NEW.kind NOT GLOB '*[^a-zA-Z0-9._/-]*' THEN NEW.kind ELSE 'unavailable' END,
        'state',NEW.state,'stage',CASE WHEN length(NEW.stage)<=96 AND NEW.stage NOT GLOB '*[^a-zA-Z0-9._/-]*' THEN NEW.stage ELSE 'unavailable' END,
        'request_id','','count',0) WHERE (SELECT COUNT(*) FROM event_log_queue)<8192;
    UPDATE event_log_status SET dropped=min(dropped+1,9223372036854775807) WHERE changes()=0;
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER security_log_insert AFTER INSERT ON audit_logs WHEN (SELECT paused FROM event_log_status WHERE id=1)=0 AND NEW.action IN('auth.bootstrap','auth.login','auth.password','auth.revoke_sessions','auth.create_credential','auth.revoke_credential','auth.revoke_self') BEGIN
    INSERT INTO event_log_queue(payload) SELECT json_object(
        'time',max(NEW.created_at,1),'category','security','level',CASE WHEN NEW.outcome='succeeded' THEN 'info' ELSE 'warn' END,
        'code',NEW.action,'task_id','','kind','','state',CASE WHEN NEW.outcome='succeeded' THEN 'succeeded' ELSE 'not_succeeded' END,
        'stage','','request_id',CASE WHEN length(NEW.request_id)=36 AND NEW.request_id NOT GLOB '*[^0-9a-f-]*' THEN NEW.request_id ELSE '' END,'count',0)
        WHERE (SELECT COUNT(*) FROM event_log_queue)<8192;
    UPDATE event_log_status SET dropped=min(dropped+1,9223372036854775807) WHERE changes()=0;
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER security_log_insert;
DROP TRIGGER task_log_update;
DROP TRIGGER task_log_insert;
DROP TABLE event_log_status;
DROP TABLE event_log_queue;
DELETE FROM settings WHERE key='event_log_epoch';
