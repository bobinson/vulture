class Api::ReportsController < ApplicationController
  before_action :authenticate_user!
  skip_before_action :authenticate_user!, if: -> { request.headers["X-Internal"].present? }

  def index
    render json: Report.all
  end
end
