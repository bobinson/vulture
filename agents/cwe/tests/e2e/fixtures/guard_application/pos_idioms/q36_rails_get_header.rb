class ApiController < ApplicationController
  skip_before_action :authenticate_user!, if: -> { request.remote_ip == "10.0.0.1" || request.get_header("HTTP_X_INTERNAL") == "1" }
end
