def to_public_message(e)
  e.message
end

def show
  run
rescue StandardError => e
  response.write(to_public_message(e)) # EXPECT: finding tp-rb-defined-public-renders
end
