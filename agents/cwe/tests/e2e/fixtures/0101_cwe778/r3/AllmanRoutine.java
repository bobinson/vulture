// Feature 0101, CWE-778 Concept A, Java (RED round 2, R2-1, R2-2, R2-10).
// Allman and K&R twins agree; `synchronized (...)` and a `() -> {` lambda are
// block statements inside the routine, not the routine; a try-with-resources
// opener resolves the window. Every identifier is invented.
public class RecordStore
{
    private Exception lastError;

    public void revokeAllKioskLogins(String userId)
    {
        try
        {
            store.deleteAll(userId);
        }
        catch (Exception e) // EXPECT: finding
        {
            this.lastError = e;
        }
    }

    public void refreshThumbnails(String userId)
    {
        try
        {
            store.deleteAll(userId);
        }
        catch (Exception e) // EXPECT: clean
        {
            this.lastError = e;
        }
    }

    public void revokeAllGrants(String userId) {
        synchronized (lock) {
            try {
                store.deleteAll(userId);
            } catch (Exception e) { // EXPECT: finding
                this.lastError = e;
            }
        }
    }

    public void refreshCounters(String userId) {
        synchronized (lock) {
            try {
                store.deleteAll(userId);
            } catch (Exception e) { // EXPECT: clean
                this.lastError = e;
            }
        }
    }

    public void rotateSigningKey(String id) {
        submit(() -> {
            try {
                vault.rotate(id);
            } catch (Exception e) { // EXPECT: finding
                this.lastError = e;
            }
        });
    }

    public void rotateThumbnail(String id) {
        submit(() -> {
            try {
                images.rotate(id);
            } catch (Exception e) { // EXPECT: clean
                this.lastError = e;
            }
        });
    }

    public void reloadPage(String id) {
        try (Reader r = open(id)) {
            store.load(r);
        } catch (IOException e) { // EXPECT: clean
            this.lastError = e;
        }
    }

    public void loadSessionKeys(String id) {
        try (Reader r = open(id)) {
            store.load(r);
        } catch (IOException e) { // EXPECT: finding
            this.lastError = e;
        }
    }
}
