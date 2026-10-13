def show
  begin
    run
  rescue StandardError => e
    # EXPECT-NEXT: finding
    response.write(e.to_s)
  end
end
