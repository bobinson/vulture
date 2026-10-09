class DownloadsController < ApplicationController
  before_action :authenticate_user!, unless: -> { params[:signature].present? }
  before_action :verify_signed_url!, if: -> { params[:signature].present? }
end
