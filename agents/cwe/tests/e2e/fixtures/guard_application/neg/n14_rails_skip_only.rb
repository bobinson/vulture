class Api::ReportsController < ApplicationController
  before_action :authenticate_user!
  skip_before_action :authenticate_user!, only: [:health]

  def health
    head :ok
  end
end
