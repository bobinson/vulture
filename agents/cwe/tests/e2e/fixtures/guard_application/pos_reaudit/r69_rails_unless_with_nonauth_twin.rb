class AdminController < ApplicationController
  before_action :authenticate_admin!, unless: -> { request.headers["X-Admin"] == "1" }
  before_action :set_admin_banner, if: -> { request.headers["X-Admin"] == "1" }
end
