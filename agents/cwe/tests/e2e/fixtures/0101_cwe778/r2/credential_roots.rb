# Feature 0101, CWE-778 Concept A: ldap, pw, pwd and passphrase name a security
# operation. Every handler keeps its failure for a later reader and logs nothing.

class DirectoryGate
  def bind_user(ldap, dn, pw)
    ldap.bind_as(base: dn, password: pw)
    nil
  rescue StandardError => e # EXPECT: finding
    @last_failure = e
  end

  def change_pwd(store, old_pwd, new_pwd)
    store.update(old_pwd, new_pwd)
    nil
  rescue StandardError => e # EXPECT: finding
    @last_failure = e
  end

  def unwrap_blob(blob, passphrase)
    vault.open(blob, passphrase)
    nil
  rescue StandardError => e # EXPECT: finding
    @last_failure = e
  end

  def check_pin(store, pin)
    begin
      store.compare(pin)
    rescue StandardError => e # EXPECT: finding
      @last_failure = e
    end
  end

  def load_spinner(store, name)
    begin
      store.read(name)
    rescue StandardError => e # EXPECT: clean
      @last_failure = e
    end
  end
end
