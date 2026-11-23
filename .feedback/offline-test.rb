require "paper_trail"
require "minitest/autorun"

class OfflineAuditTest < Minitest::Test
  def test_request_context_restores_outer_actor
    PaperTrail.request(whodunnit: "outer fixture") do
      assert_equal "outer fixture", PaperTrail.request.whodunnit
      PaperTrail.request(whodunnit: "inner fixture") do
        assert_equal "inner fixture", PaperTrail.request.whodunnit
      end
      assert_equal "outer fixture", PaperTrail.request.whodunnit
    end
  end

  def test_json_serializer_preserves_a_change_pair
    payload = { "state" => ["proposed", "approved"] }
    serializer = PaperTrail::Serializers::JSON
    assert_equal payload, serializer.load(serializer.dump(payload))
  end
end
