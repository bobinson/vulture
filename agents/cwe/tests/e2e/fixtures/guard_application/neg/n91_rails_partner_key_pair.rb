class Partners::BaseController < ApplicationController
  before_action :authenticate_partner!, if: -> { request.headers["X-Partner-Id"].present? }
  before_action :authenticate_user!, unless: -> { request.headers["X-Partner-Id"].present? }
end
