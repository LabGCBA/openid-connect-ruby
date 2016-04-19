# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'openid_connect_client/version'

Gem::Specification.new do |spec|
  spec.name          = "openid_connect_client"
  spec.version       = OpenIDConnectClient::VERSION
  spec.authors       = ["Rita Zerrizuela"]
  spec.email         = ["zeta@widcket.com"]

  spec.summary       = %q{An easy to use OpenID Connect Client for Ruby.}
  spec.description   = %q{This one is a literal, not so idiomatic port of OpenID Connect PHP. However, the due to the different nature of Ruby and PHP, usage is not an exact match. See Readme.}
  spec.homepage      = "https://github.com/LabGCBA/openid-connect-ruby.git"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
