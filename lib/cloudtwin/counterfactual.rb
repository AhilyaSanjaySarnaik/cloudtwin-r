require_relative "graph_builder"
require_relative "path_analyzer"

module CloudTwin
  class Counterfactual
    Change = Struct.new(:resource, :baseline, :proposed, :classification, keyword_init: true)

    def self.compare(baseline:, proposed:, principal_id:, action: "s3:GetObject", max_depth: 3)
      new(baseline, proposed, max_depth: max_depth).compare(principal_id: principal_id, action: action)
    end

    def initialize(baseline, proposed, max_depth: 3)
      @baseline = baseline
      @proposed = proposed
      @max_depth = max_depth
    end

    def compare(principal_id:, action:)
      before = paths(@baseline, principal_id, action).group_by(&:resource)
      after = paths(@proposed, principal_id, action).group_by(&:resource)
      (before.keys | after.keys).map do |resource|
        old_status = strongest(before[resource])
        new_status = strongest(after[resource])
        Change.new(resource: resource, baseline: old_status, proposed: new_status, classification: classify(old_status, new_status))
      end
    end

    private
    def paths(data, principal, action)
      PathAnalyzer.new(GraphBuilder.from_fixture(data), max_depth: @max_depth).analyze(principal_id: principal, action: action)
    end
    def strongest(paths)
      statuses = Array(paths).map(&:status)
      return PolicyEvaluator::ALLOWED if statuses.include?(PolicyEvaluator::ALLOWED)
      return PolicyEvaluator::UNKNOWN if statuses.include?(PolicyEvaluator::UNKNOWN)
      PolicyEvaluator::DENIED
    end
    def classify(old_status, new_status)
      return "new_access" if old_status != PolicyEvaluator::ALLOWED && new_status == PolicyEvaluator::ALLOWED
      return "access_removed" if old_status == PolicyEvaluator::ALLOWED && new_status != PolicyEvaluator::ALLOWED
      return "uncertain_change" if old_status != new_status
      "unchanged"
    end
  end
end
