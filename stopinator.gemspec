# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "stopinator/version"

Gem::Specification.new do |s|
  s.name        = "stopinator"
  s.version     = Stopinator::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["James Short"]
  s.email       = ["jshort@amplify.com"]
  s.homepage    = ""
  s.summary     = %q{Gem for stopping/starting AWS EC2 instances/environments}
  s.description = %q{Based on a simple configuration file, this gem can stop or start (with priority order) Amazon EC2 instances}

  s.add_runtime_dependency "launchy"
  s.add_runtime_dependency "aws-sdk"
  s.add_runtime_dependency "net-ssh"
  s.add_development_dependency "rspec", "~>2.5.0"

  s.files = Dir['lib/**/*.rb'] + Dir['bin/*']
  s.files += Dir['[A-Z]*'] + Dir['test/**/*']
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = ['stopinator']
  s.require_paths = ["lib"]
end
