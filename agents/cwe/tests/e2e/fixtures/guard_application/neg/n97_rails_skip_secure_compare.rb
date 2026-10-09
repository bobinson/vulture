class InternalController < ApplicationController
  skip_before_action :authenticate_user!, if: -> { ActiveSupport::SecurityUtils.secure_compare(request.headers["X-Internal-Token"].to_s, ENV["INTERNAL_TOKEN"].to_s) }
end
