class SsrfController < ApplicationController
  # Absolute URL override: the parameter supplies the whole URL, so scheme
  # and host are fully controllable.
  def absolute_url_override
    uri = URI.parse(params[:target])
    Net::HTTP.get(uri)
  end

  # Kernel-style open with an absolute, user-controlled URL.
  def open_absolute_url
    open(params[:url])
  end

  # open-uri via URI.open with a user-controlled value.
  def uri_open_user_controlled
    URI.open(params[:url])
  end

  # Fixed authority, user input only in the path: path-level exposure only.
  def fixed_authority_path_interpolation
    Net::HTTP.get(URI("https://api.internal.example.com/v1/#{params[:id]}"))
  end

  # Fixed authority built with string concatenation; input stays in the path.
  def fixed_authority_path_concat
    url = "https://api.internal.example.com/users/" + params[:id]
    HTTParty.get(url)
  end

  # Scheme-relative value: the host is controllable even though the literal
  # starts with "//". A fixed-looking prefix must not be treated as a host.
  def scheme_relative_value
    open("//#{params[:host]}/callback")
  end

  # URI.join where the base is fixed but a later argument is user controlled:
  # an absolute argument can replace the base authority.
  def uri_join_relative_override
    HTTParty.get(URI.join("https://api.internal.example.com/v1/", params[:path]).to_s)
  end

  # URI.join where only the base is involved and it is a fixed target.
  def uri_join_fixed_target
    Net::HTTP.get(URI.join("https://api.internal.example.com/", "health"))
  end

  # Entirely fixed target with no user input anywhere: no warning.
  def fully_fixed_target
    RestClient.get("https://api.internal.example.com/health")
  end

  # Fixed host passed to Net::HTTP.start: no warning.
  def net_http_fixed_host
    Net::HTTP.start("api.internal.example.com", 443, use_ssl: true)
  end

  # Host argument to Net::HTTP.start is user controlled: full authority control.
  def net_http_user_host
    Net::HTTP.start(params[:host], params[:port])
  end

  # Helper builds the URL from its argument and the result flows to a sink.
  def helper_return_value
    HTTParty.get(build_target_url(params[:target]))
  end

  # Faraday connection whose base URL is fully user controlled.
  def faraday_user_url
    Faraday.new(url: params[:target]).get("/ping")
  end

  # Faraday connection with a fixed base URL and a relative request path.
  def faraday_fixed_url
    Faraday.new(url: "https://api.internal.example.com").get("/ping")
  end

  private

  def build_target_url(target)
    URI.parse(target)
  end
end
