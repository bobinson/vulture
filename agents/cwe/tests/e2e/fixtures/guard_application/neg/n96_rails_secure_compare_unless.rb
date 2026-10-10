class InternalController < ApplicationController
  before_action :authenticate_user!, unless: -> { ActiveSupport::SecurityUtils.secure_compare(request.headers["X-Internal-Token"].to_s, ENV.fetch("INTERNAL_TOKEN")) }
end
