class FilesController < ApplicationController
  # Proper directory boundary check: no warning
  def download_guarded
    path = File.expand_path(File.join(Rails.root, "public", "uploads", params[:name]))

    if path.start_with?(File.join(Rails.root, "public", "uploads", ""))
      send_file path
    end
  end

  # Guard clause with interpolated root and trailing separator: no warning
  def download_guard_clause
    path = File.expand_path(File.join(Rails.root, "public", "uploads", params[:name]))

    return head :not_found unless path.start_with?("#{Rails.root.join("public", "uploads")}/")

    send_file path
  end

  # Literal root checked with trailing separator: no warning
  def download_literal_root
    path = File.expand_path(File.join("/var/app/uploads", params[:name]))

    return head :not_found unless path.start_with?("/var/app/uploads/")

    send_file path
  end

  # Guarded File.read: no warning
  def read_guarded
    path = File.expand_path(File.join(Rails.root, "public", "uploads", params[:name]))

    if path.start_with?(File.join(Rails.root, "public", "uploads", ""))
      File.read(path)
    end
  end

  # Prefix check without a directory boundary (`uploads_evil` passes): warning
  def download_prefix_collision
    path = File.expand_path(File.join(Rails.root, "public", "uploads", params[:name]))

    if path.start_with?(File.join(Rails.root, "public", "uploads"))
      send_file path
    end
  end

  # Use is not covered by the check: warning
  def download_outside_guard
    path = File.expand_path(File.join(Rails.root, "public", "uploads", params[:name]))

    if path.start_with?(File.join(Rails.root, "public", "uploads", ""))
      logger.info path
    end

    send_file path
  end

  # Path reassigned after the check: warning
  def download_reassigned
    path = File.expand_path(File.join(Rails.root, "public", "uploads", params[:name]))

    if path.start_with?(File.join(Rails.root, "public", "uploads", ""))
      path = params[:name]
      send_file path
    end
  end

  # Path modified in place after the check: warning
  def download_mutated
    path = File.join(Rails.root, "public", "uploads", params[:name])

    if path.start_with?(File.join(Rails.root, "public", "uploads", ""))
      path << params[:suffix]
      send_file path
    end
  end

  # cleanpath is not a confinement proof: warning
  def download_cleanpath
    path = Pathname.new(params[:name]).cleanpath.to_s

    send_file path
  end

  # Symlink resolution cannot be verified statically: warning
  def download_realpath
    root = File.realpath(Rails.root.join("public", "uploads"))
    path = File.expand_path(File.join(root, params[:name]))

    if path.start_with?("#{root}/")
      send_file path
    end
  end

  # Runtime-computed root cannot be verified statically: warning
  def download_runtime_root
    base = params[:dir]
    path = File.expand_path(File.join(base, params[:name]))

    if path.start_with?("#{base}/")
      send_file path
    end
  end

  # Unguarded user input: warning
  def download_plain
    send_file params[:path]
  end

  # Checked directory does not match where the path is built: warning
  def download_unrelated_root
    path = File.expand_path(File.join(Rails.root, "public", "uploads", params[:name]))

    if path.start_with?("/var/data/files/")
      send_file path
    end
  end

  # Guard clause using raise: no warning
  def download_raise_guard
    path = File.expand_path(File.join(Rails.root, "public", "uploads", params[:name]))

    raise ActionController::RoutingError, "Not Found" unless path.start_with?(File.join(Rails.root, "public", "uploads", ""))

    send_file path
  end
end
