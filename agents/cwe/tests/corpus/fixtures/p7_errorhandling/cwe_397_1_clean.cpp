#include <exception>

class Ledger {
 public:
  void commit(int entry) throw(LedgerFullError) {
    flush(entry);
  }
};
