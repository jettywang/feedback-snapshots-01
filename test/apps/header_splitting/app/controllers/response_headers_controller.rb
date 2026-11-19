class ResponseHeadersController < ApplicationController
  # Direct request data into a header value through the response header hash.
  def direct_header_value
    response.headers['X-Foo'] = params[:foo]
  end

  def bare_header_value
    headers['X-Baz'] = cookies[:baz]
  end

  def set_header_value
    response.set_header('X-Bar', params[:bar])
  end

  # Request data used as the header name.
  def tainted_header_name
    response.headers[params[:header_name]] = 'value'
  end

  def set_header_tainted_name
    response.set_header(params[:header_name], 'value')
  end

  # Taint through string interpolation.
  def interpolated_value
    response.headers['X-Dynamic'] = "prefix-#{params[:piece]}"
  end

  # Request header values are also request-controlled data.
  def request_header_value
    response.headers['X-Token'] = request.env['HTTP_X_TOKEN']
  end

  # A mutable local variable aliasing the response header hash.
  def local_hash_alias
    header_hash = response.headers
    header_hash['X-Alias'] = params[:aliased]
  end

  # A mutable instance variable aliasing the response header hash.
  def instance_hash_alias
    @header_hash = response.headers
    @header_hash['X-Ivar'] = params[:ivared]
  end

  # Taint reaching the headers through a bulk assignment.
  def merge_assignment
    response.headers.merge!('X-Merged' => params[:merged])
  end

  def update_assignment
    response.headers.update('X-Updated' => params[:updated])
  end

  # Provable removal of CR/LF followed by reassignment is safe.
  def gsub_removal
    clean = params[:value].to_s.gsub(/[\r\n]/, '')
    response.headers['X-Gsub'] = clean
  end

  def split_removal
    response.headers['X-Split'] = params[:value].to_s.split(/[\r\n]/).join(' ')
  end

  def delete_removal
    response.headers['X-Delete'] = params[:value].delete("\r\n")
  end

  # Safe wrapping methods after filtering cannot reintroduce CR/LF.
  def removal_then_wrapping
    response.headers['X-Wrapped'] = params[:value].gsub(/\R/, '').upcase
  end

  def filtered_interpolation
    clean = params[:value].to_s.gsub(/[\r\n]/, '')
    response.headers['X-Clean-Interp'] = "token=#{clean}"
  end

  # Filtering that does not remove CR/LF is not protection.
  def strip_is_not_enough
    response.headers['X-Strip'] = params[:value].strip
  end

  def unrelated_filter
    response.headers['X-Unrelated'] = params[:value].gsub('foo', 'bar')
  end

  def only_removes_carriage_return
    response.headers['X-Cr-Only'] = params[:value].gsub("\r", '')
  end

  # Cleaning another variable does not protect the value actually assigned.
  def sanitizes_different_variable
    clean = params[:value].gsub(/[\r\n]/, '')
    raw = params[:value]
    response.headers['X-Other-Var'] = raw
  end

  # Rejecting the request when CR/LF is present is provable protection.
  def raises_on_newline
    raw = params[:value]
    raise 'invalid header' if raw =~ /[\r\n]/
    response.headers['X-Raise-Guard'] = raw
  end

  def returns_on_newline
    raw = params[:value]
    return if raw.match?(/[\r\n]/)
    response.headers['X-Return-Guard'] = raw
  end

  def head_response_on_newline
    raw = params[:value]
    head :bad_request if raw.include?("\r\n")
    response.headers['X-Head-Guard'] = raw
  end

  def unless_guard
    raw = params[:value]
    unless raw.match?(/[\r\n]/)
      response.headers['X-Unless-Guard'] = raw
    end
  end

  # A guard on a different variable does not protect the assigned value.
  def guards_different_variable
    raw = params[:value]
    other = params[:other]
    raise 'invalid header' if other =~ /[\r\n]/
    response.headers['X-Wrong-Guard'] = raw
  end

  # Constants and fully overwritten variables are safe.
  def constant_value
    response.headers['X-Constant'] = 'static value'
    response.set_header('X-Constant-Two', 'other static value')
  end

  def overwritten_with_constant
    value = params[:value]
    value = 'safe constant'
    response.headers['X-Overwritten'] = value
  end

  # The last assignment wins, and it is tainted.
  def overwritten_with_taint
    value = 'safe constant'
    value = params[:value]
    response.headers['X-Overwritten-Tainted'] = value
  end

  def combined_or_guard
    raw = params[:value]
    if raw.include?("\n") || raw.include?("\r")
      return
    end
    response.headers['X-Or-Guard'] = raw
  end

  # Explicitly responding and returning is a valid rejection.
  def head_and_return_guard
    raw = params[:value]
    head(:bad_request) and return if raw =~ /[\r\n]/
    response.headers['X-Head-Return'] = raw
  end

  # A replacement that keeps a newline is not sufficient filtering.
  def replacement_keeps_newline
    response.headers['X-Reintroduced'] = params[:value].gsub(/[\r\n]/, "\n")
  end

  # A plain user hash is not the response header hash.
  def plain_hash_assignment
    header_hash = { 'X-Static' => 'static' }
    header_hash[params[:key]] = params[:value]
  end
end
