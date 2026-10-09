class Api::BaseController < ApplicationController
  before_action :authenticate_user_from_token!, if: -> { params[:auth_token].present? }
  before_action :authenticate_user!, unless: -> { params[:auth_token].present? }

  private

  def authenticate_user_from_token!
    user = User.find_by(authentication_token: params[:auth_token].to_s)
    if user && Devise.secure_compare(user.authentication_token, params[:auth_token])
      sign_in user, store: false
    else
      head :unauthorized
    end
  end
end
