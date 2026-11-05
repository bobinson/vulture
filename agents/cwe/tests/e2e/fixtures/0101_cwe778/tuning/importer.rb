# Feature 0101 tuning fixture (round-0 held-out, now tuning): invented identifiers.
class Importer
  def load_rows(path)
    begin
      File.read(path)
    rescue IOError => e # EXPECT: clean
      @errors << e
    end
  end

  def parse_batch(path)
    begin
      File.read(path)
    rescue IOError => e # EXPECT: clean
      return Failure.new(e)
    end
  end

  def verify_password_digest(input)
    begin
      Digest.verify(input)
    rescue IOError => e # EXPECT: finding
      return Failure.new(e)
    end
  end

  def probe(path)
    begin
      File.read(path)
    rescue IOError => e # EXPECT: finding
      nil
    end
  end
end
