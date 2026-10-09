class InternalController < ApplicationController
  skip_before_action :authenticate_user!, if: -> { request.headers["X-Internal-Key"] == Rails.application.credentials.internal_key }
end
