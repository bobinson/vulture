# Feature 0101, CWE-778 Concept A, Ruby (RED round 2, R2-2). A brace block
# `with_lock(id) {` is a block statement inside the method, not the method.
# Every identifier is invented.
class RecordStore
  def revoke_all_tokens(user_id)
    with_lock(user_id) {
      begin
        @store.delete_all(user_id)
      rescue StandardError => e # EXPECT: finding
        @last_error = e
      end
    }
  end

  def compact_pages(user_id)
    with_lock(user_id) {
      begin
        @store.delete_all(user_id)
      rescue StandardError => e # EXPECT: clean
        @last_error = e
      end
    }
  end
end
