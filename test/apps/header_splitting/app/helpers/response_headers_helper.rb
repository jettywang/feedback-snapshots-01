module ResponseHeadersHelper
  # Sink inside a helper module, reached through the mutable header hash.
  def helper_header_from_params
    response.headers['X-Helper'] = params[:helper_value]
  end

  def helper_set_header_from_params
    response.set_header('X-Helper-Set', params[:helper_set_value])
  end

  def helper_aliased_hash
    header_hash = response.headers
    header_hash['X-Helper-Alias'] = params[:helper_alias]
  end

  # A constant header in a helper is safe.
  def helper_constant_header
    response.headers['X-Helper-Constant'] = 'static'
  end
end
