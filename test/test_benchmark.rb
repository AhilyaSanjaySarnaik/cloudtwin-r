require "csv"
require "json"
require "minitest/autorun"
require "tmpdir"
require_relative "../experiments/benchmark"

class BenchmarkTest < Minitest::Test
  SCENARIOS = File.expand_path("../experiments/scenarios", __dir__)

  def test_normalizes_aws_decisions_without_fabricating_unknown_values
    assert_equal "ALLOWED", CloudTwin::Benchmark.normalize_aws_decision("allowed")
    assert_equal "DENIED", CloudTwin::Benchmark.normalize_aws_decision("explicitDeny")
    assert_equal "DENIED", CloudTwin::Benchmark.normalize_aws_decision("implicitDeny")
    assert_nil CloudTwin::Benchmark.normalize_aws_decision("newDecision")
    assert_nil CloudTwin::Benchmark.normalize_aws_decision(nil)
  end

  def test_dry_run_executes_all_scenarios_without_contacting_aws
    client = Object.new
    client.define_singleton_method(:simulate_custom_policy) { |**| raise "AWS must not be called in dry-run" }
    Dir.mktmpdir do |output_dir|
      rows = CloudTwin::Benchmark::Runner.new(scenario_dir: SCENARIOS, output_dir: output_dir).run(client: client)
      assert_equal 5, rows.length
      assert_equal %w[ALLOWED DENIED DENIED ALLOWED UNKNOWN], rows.map { |row| row["local_status"] }
      assert rows.all? { |row| row["aws_validation_status"] == "NOT_RUN" }
      assert rows.all? { |row| row["agreement"] == "NOT_VALIDATED" }
      report = JSON.parse(File.read(File.join(output_dir, "benchmark.json")))
      assert_equal "dry-run", report["mode"]
      assert_equal 0, report["validated_agreements"]
      assert_equal 5, CSV.read(File.join(output_dir, "benchmark.csv"), headers: true).length
    end
  end

  def test_live_runner_keeps_sdk_errors_separate_from_local_decisions
    client = Object.new
    client.define_singleton_method(:simulate_custom_policy) { |**| raise "simulator unavailable" }
    Dir.mktmpdir do |output_dir|
      rows = CloudTwin::Benchmark::Runner.new(scenario_dir: SCENARIOS, output_dir: output_dir, live: true).run(client: client)
      assert rows.all? { |row| row["aws_validation_status"] == "ERROR" }
      assert rows.all? { |row| row["agreement"] == "NOT_VALIDATED" }
      assert_nil rows.first.fetch("aws_status")
      assert_equal "aws_sdk_error", rows.first.fetch("aws_reason")
    end
  end

  def test_validator_preserves_missing_context_diagnostics_separately
    result = Struct.new(:eval_decision, :missing_context_values).new("implicitDeny", ["aws:PrincipalTag/approval"])
    response = Struct.new(:evaluation_results).new([result])
    client = Object.new
    client.define_singleton_method(:simulate_custom_policy) { |**| response }
    report = CloudTwin::AwsValidator.new(client: client, live: true).validate(
      policy: JSON.parse(File.read(File.join(SCENARIOS, "05_missing_context.json")))["policy"],
      action: "s3:DeleteObject", resource: "arn:aws:s3:::cloudtwin-private/report.json"
    )
    assert_equal "DENIED", report[:status]
    assert_equal ["aws:PrincipalTag/approval"], report.dig(:diagnostics, :missing_context_values)
  end

  def test_invalid_scenario_is_reported_as_an_error
    Dir.mktmpdir do |scenario_dir|
      File.write(File.join(scenario_dir, "broken.json"), JSON.generate("id" => "broken"))
      error = assert_raises(RuntimeError) do
        CloudTwin::Benchmark::Runner.new(scenario_dir: scenario_dir, output_dir: Dir.mktmpdir).run
      end
      assert_match(/invalid benchmark scenario broken/, error.message)
    end
  end
end
