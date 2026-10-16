class PasswordResetsController
  def create
    email = params[:email].to_s.downcase
    token = SecureRandom.hex(20)
    ResetMailer.deliver_reset_link(email, token)
    head :accepted
  end
end
