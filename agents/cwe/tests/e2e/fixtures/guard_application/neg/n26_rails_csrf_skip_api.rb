class Api::BaseController < ApplicationController
  protect_from_forgery with: :exception
  skip_before_action :verify_authenticity_token, if: -> { request.headers['Authorization'].present? }
  skip_before_action :verify_authenticity_token, if: -> { request.headers['X-Api-Client'].present? }
  before_action :authenticate_user!
end
