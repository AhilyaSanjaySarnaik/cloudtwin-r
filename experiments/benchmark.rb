#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "csv"
require "json"
require "optparse"
require "fileutils"
require "cloudtwin"

module CloudTwin
  module Benchmark
    module_function

    AWS_DECISIONS = {
      "allowed" => "ALLOWED",
      "explicitDeny" => "DENIED",
      "implicitDeny" => "DENIED"
    }.freeze

    def normalize_aws_decision(decision)
      AWS_DECISIONS[decision.to_s]
    end

    def agreement(local_status, aws_status, aws_run:)
      return "NOT_VALIDATED" unless aws_run
      return "UNKNOWN" if local_status == PolicyEvaluator::UNKNOWN || aws_status.nil?
      local_status == aws_status ? "AGREEMENT" : "DISAGREEMENT"
    end

    class Runner
      attr_reader :options

      def initialize(options = {})
        @options = {
          scenario_dir: File.expand_path("scenarios", __dir__),
          output_dir: File.expand_path("results", __dir__),
          live: false
        }.merge(options)
      end

      def run(client: nil)
        scenarios = scenario_paths.map { |path| JSON.parse(File.read(path)) }
        validator = CloudTwin::AwsValidator.new(client: client, live: options[:live])
        rows = scenarios.map { |scenario| evaluate(scenario, validator) }
        write_reports(rows)
        rows
      end

      private

      def scenario_paths
        paths = Dir[File.join(options[:scenario_dir], "*.json")].sort
        raise "no benchmark scenarios found in #{options[:scenario_dir]}" if paths.empty?
        paths
      end

      def evaluate(scenario, validator)
        local = PolicyEvaluator.new(scenario.fetch("policy")).evaluate(
          action: scenario.fetch("action"),
          resource: scenario.fetch("resource"),
          context: scenario.fetch("context", {}),
          principal: scenario["principal_arn"]
        )
        aws = validator.validate(
          policy: scenario.fetch("policy"),
          action: scenario.fetch("action"),
          resource: scenario.fetch("resource"),
          context: scenario.fetch("context", {}),
          principal_arn: scenario["principal_arn"]
        )
        aws_run = options[:live] && aws[:reason] == "aws_simulator"
        {
          "scenario" => scenario.fetch("id"),
          "description" => scenario["description"],
          "action" => scenario.fetch("action"),
          "resource" => scenario.fetch("resource"),
          "local_status" => local.status,
          "local_reason" => local.reason,
          "aws_status" => aws_run ? aws[:status] : nil,
          "aws_decision" => aws_run ? aws[:aws_decision] : nil,
          "aws_validation_status" => options[:live] ? (aws_run ? "VALIDATED" : "ERROR") : "NOT_RUN",
          "agreement" => CloudTwin::Benchmark.agreement(local.status, aws_run ? aws[:status] : nil, aws_run: aws_run),
          "aws_reason" => options[:live] ? aws[:reason] : "not_run",
          "aws_diagnostics" => aws[:diagnostics],
          "error" => aws[:error]
        }
      rescue KeyError, JSON::ParserError => error
        raise "invalid benchmark scenario #{scenario["id"] || "unknown"}: #{error.message}"
      end

      def write_reports(rows)
        FileUtils.mkdir_p(options[:output_dir])
        File.write(File.join(options[:output_dir], "benchmark.json"), JSON.pretty_generate({
          "mode" => options[:live] ? "live" : "dry-run",
          "validated_agreements" => rows.count { |row| row["agreement"] == "AGREEMENT" },
          "scenarios" => rows
        }) + "\n")
        columns = %w[scenario local_status local_reason aws_status aws_decision aws_validation_status agreement aws_reason error]
        CSV.open(File.join(options[:output_dir], "benchmark.csv"), "wb", write_headers: true, headers: columns) do |csv|
          rows.each { |row| csv << columns.map { |column| row[column] } }
        end
      end
    end
  end
end

def benchmark_usage
  puts <<~USAGE
    usage: ruby experiments/benchmark.rb [options]

    Run the synthetic CloudTwin-R IAM benchmark. Dry-run is the default and never contacts AWS.
        --live                       call IAM SimulateCustomPolicy (requires AWS credentials)
        --scenario-dir DIR           scenario directory (default: experiments/scenarios)
        --output-dir DIR             report directory (default: experiments/results)
    -h, --help                       show this help
  USAGE
end

if __FILE__ == $PROGRAM_NAME
  options = { live: false }
  parser = OptionParser.new do |opts|
    opts.on("--live", "call AWS IAM simulator") { options[:live] = true }
    opts.on("--scenario-dir DIR", String) { |value| options[:scenario_dir] = value }
    opts.on("--output-dir DIR", String) { |value| options[:output_dir] = value }
    opts.on("-h", "--help", "show this help") { benchmark_usage; exit 0 }
  end

  begin
    parser.parse!(ARGV)
    abort "unexpected arguments: #{ARGV.join(" ")}" unless ARGV.empty?
    client = nil
    if options[:live]
      require "aws-sdk-iam"
      client = Aws::IAM::Client.new
    end
    rows = CloudTwin::Benchmark::Runner.new(options).run(client: client)
    puts JSON.generate({ mode: options[:live] ? "live" : "dry-run", scenarios: rows.length,
                         validated_agreements: rows.count { |row| row["agreement"] == "AGREEMENT" } })
  rescue OptionParser::ParseError, LoadError, StandardError => error
    warn "benchmark failed: #{error.message}"
    exit 1
  end
end
