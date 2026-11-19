require 'brakeman/checks/base_check'
require 'brakeman/processors/lib/processor_helper'
require 'brakeman/path_confinement'

#Checks for user input in methods which open or manipulate files
class Brakeman::CheckFileAccess < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Finds possible file access using user input"

  # Explanations for why a path confinement check failed to prove
  # the path stays inside a managed directory
  LOST_PROOF_NOTES = {
    :boundary => "path confinement check on line %d does not enforce a directory boundary",
    :unrelated => "path confinement check on line %d does not match the directory the path is built from",
    :unknown => "path confinement check on line %d cannot be verified statically",
    :reassigned => "path was reassigned on line %d after the confinement check",
    :mutated => "path was modified on line %d after the confinement check",
    :not_covered => "path confinement check on line %d does not cover this use",
  }.freeze

  def run_check
    Brakeman.debug "Finding possible file access"
    methods = tracker.find_call :targets => [:Dir, :File, :IO, :Kernel, :"Net::FTP", :"Net::HTTP", :PStore, :Pathname, :Shell], :methods => [:[], :chdir, :chroot, :delete, :entries, :foreach, :glob, :install, :lchmod, :lchown, :link, :load, :load_file, :makedirs, :move, :new, :open, :read, :readlines, :rename, :rmdir, :safe_unlink, :symlink, :syscopy, :sysopen, :truncate, :unlink]

    methods.concat tracker.find_call :target => :YAML, :methods => [:load_file, :parse_file]
    methods.concat tracker.find_call :target => nil, :method => [:open]

    Brakeman.debug "Finding calls to load()"
    methods.concat tracker.find_call :target => false, :method => :load

    Brakeman.debug "Finding calls using FileUtils"
    methods.concat tracker.find_call :target => :FileUtils

    Brakeman.debug "Processing found calls"
    methods.each do |call|
      process_result call
    end
  end

  def process_result result
    return unless original? result
    call = result[:call]

    file_name = call.first_arg

    return if called_on_tempfile?(file_name) || sanitized?(file_name)

    if match = has_immediate_user_input?(file_name)
      confidence = :high
    elsif match = has_immediate_model?(file_name)
      match = Match.new(:model, match)
      confidence = :medium
    elsif tracker.options[:check_arguments] and
      match = include_user_input?(file_name)

      #Check for string building in file name
      if call?(file_name) and (file_name.method == :+ or file_name.method == :<<)
        confidence = :high
      else
        confidence = :weak
      end
    end

    if match and not temp_file_method? match.match
      proof = path_confinement result, file_name

      # Path is proven to stay inside a managed directory
      return if proof == :proven

      message = msg(msg_input(match), " used in file name")

      if proof
        message << format(" (#{LOST_PROOF_NOTES[proof.reason]})", proof.line)
      end

      warn :result => result,
        :warning_type => "File Access",
        :warning_code => :file_access,
        :message => message,
        :confidence => confidence,
        :code => call,
        :user_input => match,
        :cwe_id => [22]
    end
  end

  # When using Tempfile, there is no risk of unauthorized file access, since
  # Tempfile adds a unique string onto the end of every provided filename, and
  # ensures that the filename does not already exist in the system.
  def called_on_tempfile? file_name
    call?(file_name) && file_name.target == s(:const, :Tempfile)
  end

  def sanitized? file
    call?(file) &&
      call?(file.target) &&
      class_name(file.target.target) == :"ActiveStorage::Filename"
  end

  def temp_file_method? exp
    if call? exp
      return true if exp.call_chain.include? :tempfile

      params? exp.target and exp.method == :path
    end
  end

  # Checks whether the file path is proven to be confined to a managed
  # directory by a guard in the same method (e.g. a directory boundary
  # check with `start_with?`).
  #
  # Returns :proven, a Brakeman::PathConfinement::LostProof, or nil.
  def path_confinement result, file_name
    return nil unless sexp? file_name

    location = result[:location]
    return nil unless location and location[:type] == :class and location[:method]

    src = method_source location
    return nil unless src

    Brakeman::PathConfinement.new(src, result[:call], file_name).proof
  end

  def method_source location
    class_name = location[:class]
    method_name = location[:method]

    [tracker.controllers, tracker.models, tracker.libs].each do |collection_set|
      if collection = collection_set[class_name]
        info = collection.get_instance_method(method_name) || collection.get_class_method(method_name)
        return info.src if info
      end
    end

    nil
  end
end
