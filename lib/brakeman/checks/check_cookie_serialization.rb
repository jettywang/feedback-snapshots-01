require 'brakeman/checks/base_check'

class Brakeman::CheckCookieSerialization < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Check for use of Marshal for cookie serialization"

  KNOWN_SERIALIZERS = [:json, :marshal, :hybrid].freeze

  MARSHAL_DETAIL =
    "Signed and encrypted cookie reads authenticate cookie contents, " \
    "but do not restrict which objects are instantiated when deserializing with ".freeze

  def run_check
    serializer, result, configured = effective_serializer

    case serializer
    when :marshal
      warn_unsafe_serializer serializer, result, configured,
        MARSHAL_DETAIL, msg_code("Marshal.load")
    when :hybrid
      warn_unsafe_serializer serializer, result, configured,
        msg_code(":hybrid"), " writes JSON but still reads Marshal-serialized cookies. ",
        MARSHAL_DETAIL, msg_code("Marshal.load")
    end
  end

  private

  # Determine the cookie serializer actually in effect by combining
  # explicit configuration with Rails version defaults.
  #
  # Initializers run after config/application.rb and config/environments/*.rb
  # during Rails boot, and later assignments override earlier ones.
  # Only the final value represents the current state of the application.
  #
  # Returns [serializer, result, configured] where +result+ is a call result
  # for explicit initializer assignments (+nil+ otherwise) and +configured+
  # indicates the serializer came from explicit configuration rather than
  # a Rails version default.
  def effective_serializer
    if result = last_initializer_assignment
      return serializer_name(result[:call].first_arg), result, true
    end

    if config = tracker.config.rails.dig(:action_dispatch, :cookies_serializer)
      return serializer_name(config), nil, true
    end

    # No explicit configuration, so the Rails version determines the default
    if version_between? "4.1.0", "7.0.9.9"
      return :marshal, nil, false
    elsif version_between? "7.1.0", "9.9.9"
      return :json, nil, false
    end

    nil
  end

  # Last assignment to `cookies_serializer` in initializers,
  # since initializers are loaded in file name order and
  # later assignments override earlier ones
  def last_initializer_assignment
    results = tracker.find_call(target: :'Rails.application.config.action_dispatch', method: :cookies_serializer=)

    results.max_by do |result|
      [result[:location][:file].to_s, result[:call].line.to_i]
    end
  end

  # Map a configured value to a known serializer name, or +nil+
  # if the value cannot be determined (custom serializer, variable, etc.)
  def serializer_name value
    if symbol? value and KNOWN_SERIALIZERS.include? value.value
      value.value
    end
  end

  def warn_unsafe_serializer serializer, result, configured, *detail
    message =
      if configured
        msg("Use of unsafe cookie serialization strategy ", msg_code(serializer.inspect),
            " might lead to remote code execution. ", *detail)
      else
        msg("No cookie serializer is configured and this version of Rails defaults to ",
            msg_code(serializer.inspect), " cookie serialization, which might lead to remote code execution. ",
            *detail)
      end

    warning = {
      :warning_type => "Remote Code Execution",
      :warning_code => :unsafe_cookie_serialization,
      :message => message,
      :confidence => :medium,
      :link_path => "unsafe_deserialization",
      :cwe_id => [565, 502]
    }

    if result
      warning[:result] = result
    else
      # Configured outside initializers or implied by the Rails version default
      warning[:file] = "config/application.rb"
    end

    warn warning
  end
end
