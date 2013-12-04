require File.expand_path("../.gemspec", __FILE__)
require File.expand_path("../lib/s3encrypt/version", __FILE__)

Gem::Specification.new do |gem|
  gem.name        = "s3encrypt"
  gem.authors     = ["Chad Cloes"]
  gem.email       = ["chad_cloes@intuit.com"]
  gem.description = readme.description
  gem.summary     = readme.summary
  gem.homepage    = "https://github.com/ccloes-intuit/s3encrypt"
  gem.version     = S3Encrypt::VERSION

  gem.files       = Dir["bin/*", "lib/**/*"]
  gem.executables = Dir["bin/*"].map(&File.method(:basename))

  gem.required_ruby_version = ">= 2.0.0"

  gem.add_dependency "aws-sdk", "~> 1.18.0"
  gem.add_dependency "thor", "~> 0.18.1"

  gem.add_development_dependency "rake", "~> 10.0.4"
end
