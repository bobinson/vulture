# Feature 0101, CWE-778 Concept A in Ruby. Every identifier is invented.
class TicketLoader
  def call
    @payload = JwtLib.decode(@ticket, KEY, true, algorithm: ALG)
  rescue JwtLib::DecodeError => e # EXPECT: finding
    @error = e
  end
end

class KeyCheck
  def call
    ApiToken.verify!(@raw)
  rescue StandardError => e # EXPECT: finding
    @error = e
  end
end

class SheetImporter
  def load_rows(path)
    begin
      File.read(path)
    rescue IOError => e # EXPECT: clean
      @errors << e
    end
  end
end
