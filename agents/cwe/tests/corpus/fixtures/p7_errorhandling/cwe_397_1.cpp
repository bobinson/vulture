#include <exception>

class Ledger {
 public:
  void commit(int entry) throw(std::exception) {
    flush(entry);
  }
};
