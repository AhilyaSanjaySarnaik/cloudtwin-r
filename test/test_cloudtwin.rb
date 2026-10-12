require "json"
require "minitest/autorun"
require_relative "../lib/cloudtwin"

class CloudTwinTest < Minitest::Test
  USER = "arn:aws:iam::111122223333:user/researcher"
  BUCKET = "arn:aws:s3:::research-private/*"

  def policy(*statements)
    { "Statement" => statements }
  end

  def test_allows_matching_identity_permission
    result = CloudTwin::PolicyEvaluator.new(policy("Effect" => "Allow", "Action" => "s3:GetObject", "Resource" => BUCKET)).evaluate(action: "s3:GetObject", resource: BUCKET)
    assert_equal CloudTwin::PolicyEvaluator::ALLOWED, result.status
  end

  def test_explicit_deny_wins_over_allow
    result = CloudTwin::PolicyEvaluator.new(policy(
      {"Effect" => "Allow", "Action" => "s3:*", "Resource" => BUCKET},
      {"Effect" => "Deny", "Action" => "s3:DeleteObject", "Resource" => BUCKET}
    )).evaluate(action: "s3:DeleteObject", resource: BUCKET)
    assert_equal CloudTwin::PolicyEvaluator::DENIED, result.status
    assert_equal "explicit_deny", result.reason
  end

  def test_distinguishes_implicit_deny_from_unknown_condition
    implicit = CloudTwin::PolicyEvaluator.new(policy({"Effect" => "Allow", "Action" => "s3:GetObject", "Resource" => "other"})).evaluate(action: "s3:GetObject", resource: BUCKET)
    unknown = CloudTwin::PolicyEvaluator.new(policy({"Effect" => "Allow", "Action" => "s3:GetObject", "Resource" => BUCKET, "Condition" => {"NumericLessThan" => {"aws:MultiFactorAuthAge" => "60"}}})).evaluate(action: "s3:GetObject", resource: BUCKET)
    assert_equal "implicit_deny", implicit.reason
    assert_equal CloudTwin::PolicyEvaluator::UNKNOWN, unknown.status
  end

  def test_known_false_condition_is_denied_and_missing_context_is_unknown
    document = policy("Effect" => "Allow", "Action" => "s3:GetObject", "Resource" => BUCKET, "Condition" => {"StringEquals" => {"env" => "prod"}})
    assert_equal CloudTwin::PolicyEvaluator::DENIED, CloudTwin::PolicyEvaluator.new(document).evaluate(action: "s3:GetObject", resource: BUCKET, context: {"env" => "dev"}).status
    assert_equal CloudTwin::PolicyEvaluator::UNKNOWN, CloudTwin::PolicyEvaluator.new(document).evaluate(action: "s3:GetObject", resource: BUCKET).status
  end

  def test_graph_models_roles_trust_and_sensitive_resources
    graph = CloudTwin::GraphBuilder.from_fixture("principals" => [], "roles" => [{"arn" => "role/a", "trust_policy" => policy({"Effect" => "Allow", "Action" => "sts:AssumeRole", "Principal" => {"AWS" => USER}})}], "resources" => [{"arn" => BUCKET, "type" => "s3", "sensitive" => true}])
    assert_equal 1, graph.roles.size
    assert_equal 1, graph.trust_relationships.size
    assert graph.resources.first.sensitive
  end

  def test_path_analyzer_separates_trust_from_role_identity_permission
    data = {"principals" => [{"id" => USER, "policy" => policy("Effect" => "Deny", "Action" => "sts:AssumeRole", "Resource" => "*")}], "roles" => [{"arn" => "role/a", "trust_policy" => policy({"Effect" => "Allow", "Action" => "sts:AssumeRole", "Principal" => {"AWS" => USER}}), "policy" => policy("Effect" => "Allow", "Action" => "s3:GetObject", "Resource" => BUCKET)}], "resources" => [{"arn" => BUCKET, "sensitive" => true}]}
    paths = CloudTwin::PathAnalyzer.new(CloudTwin::GraphBuilder.from_fixture(data)).analyze(principal_id: USER)
    assert_empty paths
  end

  def test_path_analyzer_finds_trusted_role_path
    data = {"principals" => [{"id" => USER, "policy" => policy("Effect" => "Allow", "Action" => "sts:AssumeRole", "Resource" => "*")}], "roles" => [{"arn" => "role/a", "trust_policy" => policy({"Effect" => "Allow", "Action" => "sts:AssumeRole", "Principal" => {"AWS" => USER}}), "policy" => policy("Effect" => "Allow", "Action" => "s3:GetObject", "Resource" => BUCKET)}], "resources" => [{"arn" => BUCKET, "sensitive" => true}]}
    paths = CloudTwin::PathAnalyzer.new(CloudTwin::GraphBuilder.from_fixture(data)).analyze(principal_id: USER)
    assert_equal CloudTwin::PolicyEvaluator::ALLOWED, paths.first.status
    assert_equal ["role/a"], paths.first.roles
  end

  def test_counterfactual_identifies_new_access
    baseline = JSON.parse(File.read(File.expand_path("../fixtures/baseline.json", __dir__)))
    changed = JSON.parse(File.read(File.expand_path("../fixtures/changed_policy.json", __dir__)))
    changes = CloudTwin::Counterfactual.compare(baseline: baseline, proposed: changed, principal_id: USER)
    assert_equal "unchanged", changes.first.classification
    # The action-specific comparison is unchanged; a write action exposes the expansion.
    write_changes = CloudTwin::Counterfactual.compare(baseline: baseline, proposed: changed, principal_id: USER, action: "s3:PutObject")
    assert_equal "new_access", write_changes.first.classification
  end

  def test_aws_validator_is_dry_run_by_default
    result = CloudTwin::AwsValidator.new.validate(policy: policy("Effect" => "Allow"), action: "s3:GetObject", resource: BUCKET)
    assert_equal "DRY_RUN", result[:status]
    assert_nil result[:aws_decision]
  end

  def test_aws_validator_normalizes_all_simulator_decisions
    { "allowed" => "ALLOWED", "explicitDeny" => "DENIED", "implicitDeny" => "DENIED" }.each do |decision, expected_status|
      result = aws_result(decision)
      assert_equal expected_status, result[:status]
      assert_equal decision, result[:aws_decision]
      assert_equal "aws_simulator", result[:reason]
    end
  end

  def test_aws_validator_returns_unknown_for_missing_or_unsupported_decisions
    [nil, "newDecision"].each do |decision|
      result = aws_result(decision)
      assert_equal "UNKNOWN", result[:status]
      decision.nil? ? assert_nil(result[:aws_decision]) : assert_equal(decision, result[:aws_decision])
      assert_equal "unsupported_or_missing_decision", result[:reason]
    end
  end

  def test_aws_validator_returns_unknown_for_empty_results
    client = Object.new
    client.define_singleton_method(:simulate_custom_policy) { |**| Struct.new(:evaluation_results).new([]) }
    result = CloudTwin::AwsValidator.new(client: client, live: true).validate(policy: policy("Effect" => "Allow"), action: "s3:GetObject", resource: BUCKET)
    assert_equal "UNKNOWN", result[:status]
    assert_equal "empty_response", result[:reason]
    assert JSON.generate(result)
  end

  def test_aws_validator_returns_unknown_for_sdk_exceptions_without_raw_response
    client = Object.new
    client.define_singleton_method(:simulate_custom_policy) { |**| raise "simulator unavailable" }
    result = CloudTwin::AwsValidator.new(client: client, live: true).validate(policy: policy("Effect" => "Allow"), action: "s3:GetObject", resource: BUCKET)
    assert_equal "UNKNOWN", result[:status]
    assert_equal "aws_sdk_error", result[:reason]
    assert_equal "RuntimeError", result[:error]
    refute result.key?(:raw)
    assert JSON.generate(result)
  end

  def aws_result(decision)
    response = Struct.new(:evaluation_results).new([Struct.new(:eval_decision).new(decision)])
    client = Object.new
    client.define_singleton_method(:simulate_custom_policy) do |**params|
      raise "unexpected policy" unless params[:action_names] == ["s3:GetObject"]
      response
    end
    CloudTwin::AwsValidator.new(client: client, live: true).validate(policy: policy("Effect" => "Allow"), action: "s3:GetObject", resource: BUCKET)
  end
end
