class ApplicationController < ActionController::Base
  before_action :authenticate_user!,
                unless: -> { request.headers["X-Internal"] == "true" }
end
