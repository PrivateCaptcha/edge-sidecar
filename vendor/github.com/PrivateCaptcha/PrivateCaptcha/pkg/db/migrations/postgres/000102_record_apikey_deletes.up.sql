CREATE OR REPLACE TRIGGER deleted_record_insert AFTER DELETE ON backend.apikeys
   FOR EACH ROW EXECUTE FUNCTION backend.deleted_record_insert();
