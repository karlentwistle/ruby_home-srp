
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ruby_home-srp/version'

Gem::Specification.new do |spec|
  spec.name          = 'ruby_home-srp'
  spec.version       = Rubyhome::SRP::VERSION
  spec.authors       = ['Karl Entwistle']
  spec.email         = ['karl@entwistle.com']
  spec.summary       = 'Secure Remote Password protocol SRP-6a-HAP'
  spec.description   = <<~DESCRIPTION
    Secure Remote Password protocol (SRP-6a) with HAP modifications
  DESCRIPTION
  spec.homepage      = 'https://github.com/karlentwistle/ruby_home-srp'

  spec.files         = Dir.glob('lib/**/*')
  spec.test_files    = Dir.glob('spec/*')
  spec.require_paths = ['lib']

  spec.add_dependency 'srp-rb', '1.0.1'

  spec.add_development_dependency 'rake', '~> 12.3'
  spec.add_development_dependency 'rspec', '~> 3.0'
end
