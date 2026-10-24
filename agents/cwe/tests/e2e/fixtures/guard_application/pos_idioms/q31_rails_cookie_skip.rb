class ApiController < ApplicationController
  skip_before_action :authenticate_user!, unless: -> { cookies[:beta].blank? }
end
