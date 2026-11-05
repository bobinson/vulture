def show
  run
rescue StandardError => ex
  # EXPECT-NEXT: finding  ruby to s
  response.write(ex.to_s)
end
