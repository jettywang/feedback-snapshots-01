class YamlConfigsController < ApplicationController
  PLAIN_CLASSES = [Symbol, Date].freeze
  OBJECT_CLASSES = [Symbol, ImportJob].freeze
  CHANGED_CLASSES = [Symbol]

  def plain_data_only
    # No options: only plain data can be deserialized
    YAML.safe_load(params[:yaml])

    # Only plain data classes are permitted
    YAML.safe_load(params[:yaml], permitted_classes: [Symbol, Date])

    # Plain data classes via a constant, explicit permitted symbols
    YAML.safe_load(params[:yaml], permitted_classes: PLAIN_CLASSES, permitted_symbols: [:name])

    # Empty permitted class list
    YAML.safe_load(params[:yaml], permitted_classes: [])
  end

  def permitted_objects
    # Explicitly permits restoring ImportJob objects
    YAML.safe_load(params[:yaml], permitted_classes: [Symbol, ImportJob])

    # Same, but the list comes from a constant
    YAML.safe_load(params[:yaml], permitted_classes: OBJECT_CLASSES)
  end

  def unknown_classes
    # Class list is computed at runtime
    YAML.safe_load(params[:yaml], permitted_classes: allowed_class_list)

    # Whitelist is modified after assignment, final contents unknown
    YAML.safe_load(params[:yaml], permitted_classes: CHANGED_CLASSES)
  end

  def local_list
    # Local alias modified before use
    allowed = [Symbol]
    allowed << ImportJob
    YAML.safe_load(params[:yaml], permitted_classes: allowed)
  end

  def with_aliases
    # YAML aliases enabled for untrusted input
    YAML.safe_load(params[:yaml], aliases: true)
  end

  def not_user_input
    YAML.safe_load("--- {}\n", permitted_classes: [ImportJob])
  end

  private

  def allowed_class_list
    [Symbol]
  end
end
