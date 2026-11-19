module UsersHelper
  def html_safe_wrapper(value)
    content_tag(:span, value)
  end

  def raw_wrapper(value)
    raw(value)
  end

  def js_wrapper(value)
    j(value)
  end

  def json_wrapper(value)
    raw(value.to_json)
  end

  def passthrough(value)
    value
  end
end
