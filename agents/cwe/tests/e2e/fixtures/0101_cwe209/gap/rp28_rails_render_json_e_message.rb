def show
  run
rescue => e
  # EXPECT-NEXT: clean  known-gap rails render json e message
  render json: { error: e.message }, status: 500
end
