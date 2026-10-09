class AdminController < ApplicationController
  before_action :authenticate_admin!, if: -> { params[:admin].present? }
end
