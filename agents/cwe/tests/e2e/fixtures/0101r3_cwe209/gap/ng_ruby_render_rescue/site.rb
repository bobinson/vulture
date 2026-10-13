class ItemsController
  def show
    item = Store.read(params[:id])
    render json: item
  rescue StandardError => e
    render json: { error: e.message }, status: 500 # EXPECT: clean gap-NG-render-keyword
  end
end
