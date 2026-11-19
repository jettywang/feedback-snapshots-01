# frozen_string_literal: true

# Offline test shim: Ruby >= 3.4 natively supports every feature ActionPolicy
# uses through ruby-next (`it` block param, `then`, pattern matching), so the
# transpiler is a no-op here. Only used when the real `ruby-next` gem is absent.
module RubyNext
end
