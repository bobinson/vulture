# pins: a Ruby action opens params[:file] directly - a language with no v1 AST profile, so the regex tier owns it (unsupported tally)
def show
  File.open(params[:file]) { |f| send_data f.read }
end
