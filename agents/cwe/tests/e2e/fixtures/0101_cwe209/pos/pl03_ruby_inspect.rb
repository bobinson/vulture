def show
  run
rescue StandardError => e
  # EXPECT-NEXT: finding  ruby inspect
  response.write(e.inspect)
end
