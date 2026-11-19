RailsScriptContext::Application.routes.draw do
  resources :users do
    collection do
      get :helpers
      get :edge
      get :dynamic
      get :conditional
      get :unknown
    end
  end
end
