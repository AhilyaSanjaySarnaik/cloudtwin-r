require_relative "policy_evaluator"

module CloudTwin
  class PathAnalyzer
    Path = Struct.new(:principal, :resource, :roles, :status, :reasons, keyword_init: true)

    def initialize(graph, max_depth: 3)
      @graph = graph
      @max_depth = max_depth
    end

    def analyze(principal_id:, action: "s3:GetObject", context: {})
      principal = @graph.principals.find { |p| p.id == principal_id }
      raise ArgumentError, "unknown principal: #{principal_id}" unless principal
      @graph.resources.select(&:sensitive).map do |resource|
        search(principal, resource, action, context, [], 0)
      end.flatten
    end

    private

    def search(principal, resource, action, context, roles, depth)
      identity = PolicyEvaluator.new(principal.policy).evaluate(action: action, resource: resource.arn, context: context)
      results = []
      if identity.allowed?
        results << Path.new(principal: principal.id, resource: resource.arn, roles: roles, status: PolicyEvaluator::ALLOWED, reasons: ["identity_permission"])
      elsif identity.unknown?
        results << Path.new(principal: principal.id, resource: resource.arn, roles: roles, status: PolicyEvaluator::UNKNOWN, reasons: [identity.reason])
      end
      return results if depth >= @max_depth

      @graph.roles.each do |role|
        caller_assume = PolicyEvaluator.new(principal.policy).evaluate(action: "sts:AssumeRole", resource: role.arn, context: context)
        next if caller_assume.denied?
        trust = PolicyEvaluator.new(role.trust_policy).evaluate(action: "sts:AssumeRole", resource: role.arn, principal: principal.id, context: context)
        next if trust.denied?
        role_result = PolicyEvaluator.new(role.policy).evaluate(action: action, resource: resource.arn, context: context)
        status = if caller_assume.unknown? || trust.unknown? || role_result.unknown?
                   PolicyEvaluator::UNKNOWN
                 elsif role_result.allowed?
                   PolicyEvaluator::ALLOWED
                 else
                   next
                 end
        results << Path.new(principal: principal.id, resource: resource.arn, roles: roles + [role.arn], status: status, reasons: ["caller_assume_role", "trust_permission", role_result.reason])
      end
      results
    end
  end
end
