class PostsController < ApplicationController
  before_action :authenticate_user!, if: -> { params[:action] != "index" }
end
