-- Deleting and renaming need the new delete action. Admins get it where
-- they may replace files by default; changed rules are left alone.
INSERT INTO casbin_rule (ptype, v0, v1, v2)
SELECT 'p', 'admin', '/*', 'delete'
WHERE EXISTS (
    SELECT 1 FROM casbin_rule
    WHERE (ptype, v0, v1, v2, v3, v4, v5) = ('p', 'admin', '/*', 'overwrite', '', '', ''))
ON CONFLICT DO NOTHING;
