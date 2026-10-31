// Feature 0101, CWE-778 Concept A, Allman braces (RED round 2, R2-1 and R2-2).
// The routine declaration sits on the line ABOVE a lone `{`; it is part of the
// guarded window, so a security routine reports and its non-security twin is
// excused, in Allman and in K&R. `lock (...)` and `using (...)` are block
// statements, not declarations: the walk continues to the routine above them.
// Every identifier is invented.
public class RecordStore
{
    private Exception _lastError;

    public void RevokeAllKioskLogins(string userId)
    {
        try
        {
            _store.DeleteAll(userId);
        }
        catch (Exception ex) // EXPECT: finding
        {
            this._lastError = ex;
        }
    }

    public void RevokeAllKioskLoginsKr(string userId) {
        try {
            _store.DeleteAll(userId);
        } catch (Exception ex) { // EXPECT: finding
            this._lastError = ex;
        }
    }

    public void RefreshThumbnails(string userId)
    {
        try
        {
            _store.DeleteAll(userId);
        }
        catch (Exception ex) // EXPECT: clean
        {
            this._lastError = ex;
        }
    }

    public void RefreshThumbnailsKr(string userId) {
        try {
            _store.DeleteAll(userId);
        } catch (Exception ex) { // EXPECT: clean
            this._lastError = ex;
        }
    }

    public void RevokeAllGrants(string userId)
    {
        lock (_sync)
        {
            try
            {
                _store.DeleteAll(userId);
            }
            catch (Exception ex) // EXPECT: finding
            {
                this._lastError = ex;
            }
        }
    }

    public void RefreshCounters(string userId)
    {
        lock (_sync)
        {
            try
            {
                _store.DeleteAll(userId);
            }
            catch (Exception ex) // EXPECT: clean
            {
                this._lastError = ex;
            }
        }
    }

    public void RevokeAllTokens(string userId)
    {
        using (var tx = _db.Begin())
        {
            try
            {
                _store.DeleteAll(userId);
            }
            catch (Exception ex) // EXPECT: finding
            {
                this._lastError = ex;
            }
        }
    }

    public void CompactPages(string userId)
    {
        using (var tx = _db.Begin())
        {
            try
            {
                _store.DeleteAll(userId);
            }
            catch (Exception ex) // EXPECT: clean
            {
                this._lastError = ex;
            }
        }
    }
}
