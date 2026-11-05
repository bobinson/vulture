CREATE OR REPLACE FUNCTION best_root(norm text) RETURNS text AS $$
DECLARE best text;
BEGIN
    SELECT r.root INTO best
      FROM (SELECT DISTINCT parent_of(strip_runmode(s.path)) AS root  -- EXPECT: clean
              FROM sources s) r;
    RETURN best;
END $$ LANGUAGE plpgsql;
