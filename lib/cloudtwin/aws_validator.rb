module CloudTwin
  class AwsValidator
    def initialize(client: nil, live: false)
      @live = live
      @client = client
    end

    def validate(policy:, action:, resource:, context: {}, principal_arn: nil)
      return { status: "DRY_RUN", reason: "AWS simulator not called" } unless @live
      raise ArgumentError, "live validation requires an injected IAM client" unless @client
      require "json"
      params = { policy_input_list: [JSON.generate(policy)], action_names: [action], resource_arns: [resource] }
      params[:context_entries] = context.map { |key, value| { context_key_name: key.to_s, context_key_values: Array(value).map(&:to_s), context_key_type: "string" } }
      params[:caller_arn] = principal_arn if principal_arn
      response = @client.simulate_custom_policy(**params)
      result = response.evaluation_results.first
      { status: result.eval_decision.to_s.upcase, decision: result.eval_decision, raw: result }
    end
  end
end
