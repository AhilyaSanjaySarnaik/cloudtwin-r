module CloudTwin
  class GraphBuilder
    Graph = Struct.new(:principals, :roles, :trust_relationships, :resources, keyword_init: true)
    Principal = Struct.new(:id, :type, :policy, keyword_init: true)
    Role = Struct.new(:arn, :name, :policy, :trust_policy, keyword_init: true)
    Resource = Struct.new(:arn, :type, :sensitive, keyword_init: true)
    Trust = Struct.new(:from, :to, :policy, keyword_init: true)

    def self.from_fixture(data)
      new(data).build
    end

    def initialize(data)
      @data = data
    end

    def build
      principals = Array(@data["principals"]).map { |p| Principal.new(id: p["id"], type: p["type"], policy: p["policy"] || { "Statement" => [] }) }
      roles = Array(@data["roles"]).map do |r|
        Role.new(arn: r["arn"], name: r["name"] || r["arn"].to_s.split("/").last, policy: r["policy"] || { "Statement" => [] }, trust_policy: r["trust_policy"] || { "Statement" => [] })
      end
      resources = Array(@data["resources"]).map { |r| Resource.new(arn: r["arn"], type: r["type"], sensitive: !!r["sensitive"]) }
      trusts = roles.map { |r| Trust.new(from: r.trust_policy, to: r.arn, policy: r.trust_policy) }
      Graph.new(principals: principals, roles: roles, trust_relationships: trusts, resources: resources)
    end
  end
end
