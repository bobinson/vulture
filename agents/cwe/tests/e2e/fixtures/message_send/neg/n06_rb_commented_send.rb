class PasswordResetsController
  def create
    email = params[:email].to_s.downcase
    # ResetMailer.deliver_reset_link(email, token)
    head :accepted
  end
end
