class Api::V1::BaseController < ActionController::API
  before_action :authenticate_with_hmac!, if: -> { request.headers["X-Signature"].present? }
  before_action :doorkeeper_authorize!, unless: -> { request.headers["X-Signature"].present? }
end
