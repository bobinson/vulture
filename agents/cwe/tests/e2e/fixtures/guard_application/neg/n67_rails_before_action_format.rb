class ApiController < ApplicationController
  before_action :authenticate_user!, unless: -> { request.format.json? }
end
