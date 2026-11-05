def show
  run
rescue StandardError => e
  # EXPECT-NEXT: finding  ruby rescue
  response.write(e.message)
end
