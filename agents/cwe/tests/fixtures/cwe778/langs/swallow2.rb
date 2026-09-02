def a
  x = risky rescue nil
  y = risky
  rescue_from StandardError, with: :handler
  begin
    risky
  ensure
    cleanup
  end
end
