Outcome = Struct.new(:ok, :error)

def load_ledger(id)
  Store.read(id)
  Outcome.new(true, nil)
rescue StandardError => e
  Outcome.new(false, e.message)
end

def show(res, id)
  outcome = load_ledger(id)
  res.write(outcome.error) # EXPECT: finding tp-positional
end
