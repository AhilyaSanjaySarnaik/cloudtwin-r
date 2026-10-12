module CloudTwin
  class PolicyEvaluator
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    UNKNOWN = "UNKNOWN"
    Result = Struct.new(:status, :reason, :matched_statements, keyword_init: true) do
      def allowed? = status == ALLOWED
      def denied? = status == DENIED
      def unknown? = status == UNKNOWN
      def to_s = status
    end

    SUPPORTED_CONDITIONS = %w[StringEquals StringLike ArnEquals ArnLike Bool].freeze

    def initialize(document)
      @statements = Array(document.is_a?(Hash) ? document["Statement"] || document[:Statement] : document)
    end

    def evaluate(action:, resource:, context: {}, principal: nil)
      applicable = []
      uncertain = []
      @statements.each do |statement|
        next unless statement.is_a?(Hash)
        next unless effect(statement) && action_match?(statement, action) && resource_match?(statement, resource)
        principal_match = principal_match?(statement, principal)
        next if principal_match == false
        if principal_match == :unknown
          uncertain << statement
          next
        end
        condition = conditions_match(statement["Condition"] || statement[:Condition], context)
        if condition == :unknown
          uncertain << statement
        elsif condition
          applicable << statement
        end
      end

      explicit_denies = applicable.select { |s| effect(s).casecmp?("Deny") }
      return Result.new(status: DENIED, reason: "explicit_deny", matched_statements: explicit_denies) unless explicit_denies.empty?
      allows = applicable.select { |s| effect(s).casecmp?("Allow") }
      return Result.new(status: ALLOWED, reason: "explicit_allow", matched_statements: allows) unless allows.empty? || !uncertain.empty?
      return Result.new(status: UNKNOWN, reason: "missing_or_unsupported_condition", matched_statements: uncertain) unless uncertain.empty?
      Result.new(status: DENIED, reason: "implicit_deny", matched_statements: [])
    end

    private

    def effect(s) = s["Effect"] || s[:Effect]
    def values(value) = Array(value).map(&:to_s)

    def action_match?(s, action)
      values(s["Action"] || s[:Action]).any? { |pattern| wildcard_match?(pattern, action) } &&
        !values(s["NotAction"] || s[:NotAction]).any? { |pattern| wildcard_match?(pattern, action) }
    end

    def resource_match?(s, resource)
      patterns = values(s["Resource"] || s[:Resource])
      patterns.empty? || patterns.any? { |pattern| wildcard_match?(pattern, resource) }
    end

    def principal_match?(s, principal)
      expected = s["Principal"] || s[:Principal]
      return true if expected.nil? && principal.nil?
      return false if expected.nil?
      return :unknown if principal.nil?
      entries = expected.is_a?(Hash) ? expected.values.flatten : Array(expected)
      entries.any? { |entry| wildcard_match?(entry.to_s, principal.to_s) }
    end

    def wildcard_match?(pattern, value)
      Regexp.escape(pattern.to_s).gsub('\\*', '.*').gsub('\\?', '.')
        .then { |expression| Regexp.new("\\A#{expression}\\z") =~ value.to_s }
    end

    def conditions_match(conditions, context)
      return true if conditions.nil? || conditions.empty?
      conditions.each do |operator, clauses|
        return :unknown unless SUPPORTED_CONDITIONS.include?(operator.to_s)
        clauses.each do |key, expected|
          actual = if context.key?(key.to_s)
                     context[key.to_s]
                   elsif context.key?(key.to_sym)
                     context[key.to_sym]
                   end
          return :unknown if actual.nil?
          expected_values = values(expected)
          actual_values = values(actual)
          matches = case operator.to_s
                    when "StringEquals", "ArnEquals" then actual_values.any? { |a| expected_values.include?(a) }
                    when "StringLike", "ArnLike" then actual_values.any? { |a| expected_values.any? { |e| wildcard_match?(e, a) } }
                    when "Bool" then expected_values.include?(actual.to_s.downcase)
                    end
          return false unless matches
        end
      end
      true
    end
  end
end
