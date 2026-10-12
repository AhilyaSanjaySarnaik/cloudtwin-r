module CloudTwin
  class AwsValidator
    DECISION_STATUS = {
      "allowed" => "ALLOWED",
      "explicitDeny" => "DENIED",
      "implicitDeny" => "DENIED"
    }.freeze

    def initialize(client: nil, live: false)
      @live = live
      @client = client
    end

    def validate(policy:, action:, resource:, context: {}, principal_arn: nil)
      return report(status: "DRY_RUN", reason: "AWS simulator not called") unless @live
      return report(status: "UNKNOWN", reason: "live validation requires an injected IAM client") unless @client

      require "json"
      params = { policy_input_list: [JSON.generate(policy)], action_names: [action], resource_arns: [resource] }
      params[:context_entries] = context.map { |key, value| { context_key_name: key.to_s, context_key_values: Array(value).map(&:to_s), context_key_type: "string" } }
      params[:caller_arn] = principal_arn if principal_arn
      response = begin
        @client.simulate_custom_policy(**params)
      rescue StandardError => error
        return report(status: "UNKNOWN", reason: "aws_sdk_error", error: error.class.name)
      end
      results = response.respond_to?(:evaluation_results) ? response.evaluation_results : nil
      return report(status: "UNKNOWN", reason: "empty_response") if results.nil? || results.empty?

      result = results.first
      aws_decision = result.respond_to?(:eval_decision) ? result.eval_decision : nil
      status = DECISION_STATUS[aws_decision.to_s]
      return report(status: "UNKNOWN", reason: "unsupported_or_missing_decision", aws_decision: aws_decision) unless status

      report(status: status, reason: "aws_simulator", aws_decision: aws_decision)
    end

    private

    def report(status:, reason:, aws_decision: nil, error: nil)
      result = { status: status, reason: reason, aws_decision: aws_decision }
      result[:error] = error if error
      result
    end
  end
end
