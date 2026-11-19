class RansackController < ApplicationController
  def search
    FiniteChild.ransack(params[:q])
    ConditionalFiniteChild.ransack(params[:q])
    NarrowChild.ransack(params[:q])
    FallbackAllowList.ransack(params[:q])
    DynamicAllowList.ransack(params[:q])
    ConcatenatedAllowList.ransack(params[:q])
    AllAssociations.ransack(params[:q])
    ConditionalFallback.ransack(params[:q])
  end
end
