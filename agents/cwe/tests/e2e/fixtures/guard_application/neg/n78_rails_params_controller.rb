class ApplicationController < ActionController::Base
  before_action :authenticate_user!, unless: -> { params[:controller] == "sessions" }
end
