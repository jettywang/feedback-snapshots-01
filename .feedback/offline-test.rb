require "sidekiq"
require "sidekiq/testing"
require "minitest/autorun"

class OfflineWorker
  include Sidekiq::Job
  sidekiq_options queue: :feedback

  def perform(_value)
  end
end

class OfflineQueueTest < Minitest::Test
  def test_enqueue_preserves_queue_and_payload
    Sidekiq::Testing.fake! do
      OfflineWorker.clear
      jid = OfflineWorker.perform_async("example")
      job = OfflineWorker.jobs.fetch(0)
      assert_equal jid, job.fetch("jid")
      assert_equal "feedback", job.fetch("queue")
      assert_equal ["example"], job.fetch("args")
    ensure
      OfflineWorker.clear
    end
  end
end
